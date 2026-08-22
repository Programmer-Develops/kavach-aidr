"""
config.py — Hardware-adaptive configuration for KAVACH-AIDR.

Automatically detects available compute (CPU/GPU) and selects the best
local LLM model that will run reliably on that hardware.
No manual configuration required — works from a Raspberry Pi to a GPU server.
"""

import os
import shutil
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ── Project root (kavach-aidr/) ────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR   = PROJECT_ROOT / "models"
DATA_DIR     = PROJECT_ROOT / "data"
REPORTS_DIR  = PROJECT_ROOT / "reports"
AUDIT_DB     = PROJECT_ROOT / "audit" / "kavach_audit.db"


# ── Supported local models (non-Chinese, open-source) ──────────────────────
# All models are Microsoft or Meta — US-origin, fully auditable
MODELS = {
    "phi3-mini": {
        "name"        : "Phi-3-mini-3.8B-Q4_K_M",
        "filename"    : "Phi-3-mini-4k-instruct-q4.gguf",
        "url"         : "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf",
        "ram_gb_min"  : 2.5,
        "vram_gb_min" : 0,        # Runs on CPU only
        "n_ctx"       : 4096,
        "origin"      : "Microsoft (USA)",
        "description" : "Fastest. Works on ANY hardware including CPU-only.",
    },
    "codellama-7b": {
        "name"        : "CodeLlama-7B-Q4_K_M",
        "filename"    : "codellama-7b-instruct.Q4_K_M.gguf",
        "url"         : "https://huggingface.co/TheBloke/CodeLlama-7B-Instruct-GGUF/resolve/main/codellama-7b-instruct.Q4_K_M.gguf",
        "ram_gb_min"  : 5.0,
        "vram_gb_min" : 4.0,
        "n_ctx"       : 4096,
        "origin"      : "Meta AI (USA)",
        "description" : "Better code understanding. Needs 4GB+ VRAM or 8GB+ RAM.",
    },
    "codellama-13b": {
        "name"        : "CodeLlama-13B-Q4_K_M",
        "filename"    : "codellama-13b-instruct.Q4_K_M.gguf",
        "url"         : "https://huggingface.co/TheBloke/CodeLlama-13B-Instruct-GGUF/resolve/main/codellama-13b-instruct.Q4_K_M.gguf",
        "ram_gb_min"  : 9.0,
        "vram_gb_min" : 8.0,
        "n_ctx"       : 4096,
        "origin"      : "Meta AI (USA)",
        "description" : "Best accuracy. Needs 8GB+ VRAM.",
    },
}


@dataclass
class HardwareProfile:
    """Detected hardware capabilities of the current machine."""
    cpu_cores     : int   = 4
    ram_gb        : float = 8.0
    has_gpu       : bool  = False
    vram_gb       : float = 0.0
    gpu_name      : str   = "None"
    platform      : str   = "unknown"
    n_gpu_layers  : int   = 0      # Layers to offload to GPU (0 = CPU-only)


@dataclass
class KavachConfig:
    """Full runtime configuration for the KAVACH-AIDR pipeline."""
    hardware      : HardwareProfile = field(default_factory=HardwareProfile)
    model_key     : str  = "phi3-mini"
    model_path    : Optional[Path] = None
    n_ctx         : int  = 4096
    n_threads     : int  = 4
    n_gpu_layers  : int  = 0
    max_tokens    : int  = 1024
    temperature   : float = 0.1      # Low temp = deterministic, factual patches
    semgrep_bin   : str  = "semgrep"
    bandit_bin    : str  = "bandit"
    audit_db_path : Path = AUDIT_DB
    reports_dir   : Path = REPORTS_DIR
    hmac_secret   : str  = os.environ.get("KAVACH_HMAC_SECRET", "KAVACH-AIDR-DEFAULT-SECRET-CHANGE-IN-PROD")
    verbose       : bool = False


def detect_hardware() -> HardwareProfile:
    """Auto-detect CPU, RAM, and GPU capabilities."""
    import psutil

    profile = HardwareProfile()
    profile.cpu_cores = os.cpu_count() or 4
    profile.ram_gb    = psutil.virtual_memory().total / (1024 ** 3)
    profile.platform  = platform.system()

    # ── GPU detection (optional — gracefully skips if not available) ────
    try:
        import subprocess
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split(",")
            profile.has_gpu  = True
            profile.gpu_name = parts[0].strip()
            profile.vram_gb  = float(parts[1].strip()) / 1024  # MiB → GiB
    except Exception:
        pass  # No GPU or nvidia-smi not available — that's fine

    return profile


def select_model(hw: HardwareProfile) -> str:
    """
    Select the best available model key based on hardware.
    Priority: best accuracy that fits in available memory.
    Falls back to phi3-mini which runs on any CPU.
    """
    # Check from best → lightest
    for key in ["codellama-13b", "codellama-7b", "phi3-mini"]:
        spec = MODELS[key]
        if hw.has_gpu and hw.vram_gb >= spec["vram_gb_min"]:
            return key
        if not hw.has_gpu and hw.ram_gb >= spec["ram_gb_min"]:
            # CPU mode: only phi3-mini and codellama-7b are practical on CPU
            if spec["vram_gb_min"] == 0 or hw.ram_gb >= 10:
                return key
    return "phi3-mini"  # Always works


def build_config(model_override: Optional[str] = None,
                 verbose: bool = False) -> KavachConfig:
    """
    Build a complete runtime config by auto-detecting hardware and
    selecting the appropriate local LLM model.
    """
    hw        = detect_hardware()
    model_key = model_override or select_model(hw)
    spec      = MODELS[model_key]

    # Find model file
    model_path = MODELS_DIR / spec["filename"]

    # GPU layer offloading
    n_gpu_layers = 0
    if hw.has_gpu and hw.vram_gb >= spec["vram_gb_min"]:
        n_gpu_layers = -1  # -1 = offload ALL layers to GPU (fastest)

    # CPU thread count: leave 1 core free for OS
    n_threads = max(1, hw.cpu_cores - 1)

    # Ensure directories exist
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)

    cfg = KavachConfig(
        hardware      = hw,
        model_key     = model_key,
        model_path    = model_path if model_path.exists() else None,
        n_ctx         = spec["n_ctx"],
        n_threads     = n_threads,
        n_gpu_layers  = n_gpu_layers,
        audit_db_path = AUDIT_DB,
        reports_dir   = REPORTS_DIR,
        verbose       = verbose,
    )
    return cfg


def check_tools() -> dict:
    """
    Check which external tools are installed and available on PATH.
    Returns a dict of {tool_name: True/False}.
    """
    tools = {
        "semgrep" : shutil.which("semgrep") is not None,
        "bandit"  : shutil.which("bandit")  is not None,
    }
    return tools
