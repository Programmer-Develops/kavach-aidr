# 📥 KAVACH-AIDR — Model Download Guide

Models run **100% locally** — downloaded once, used offline forever.
No internet required after download. No data ever leaves your machine.

---

## Step 1: Choose Your Model

| Model | Company | RAM Needed | Best For |
|---|---|---|---|
| **Phi-3-mini** (recommended) | Microsoft 🇺🇸 | ~2.5 GB RAM | CPU-only, fast, works anywhere |
| **CodeLlama-7B** | Meta 🇺🇸 | ~4 GB VRAM | Better code reasoning, needs GPU |
| **CodeLlama-13B** | Meta 🇺🇸 | ~8 GB VRAM | Best accuracy, needs strong GPU |

---

## Step 2: Download (one-time, then fully offline)

### Option A — Automatic (recommended)

```bash
# Install huggingface_hub for download utility
pip install huggingface_hub

# Download Phi-3-mini (works on any CPU — start here)
python -c "
from huggingface_hub import hf_hub_download
import shutil, pathlib

path = hf_hub_download(
    repo_id='microsoft/Phi-3-mini-4k-instruct-gguf',
    filename='Phi-3-mini-4k-instruct-q4.gguf',
    local_dir='models/'
)
print(f'Downloaded to: {path}')
"
```

### Option B — Manual Download

1. Go to: https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf
2. Download: `Phi-3-mini-4k-instruct-q4.gguf`
3. Place it in this `models/` directory

### Option C — wget/curl

```bash
# Phi-3-mini (2.2 GB)
wget -P models/ "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf"

# CodeLlama-7B (4.1 GB) — if you have a GPU
wget -P models/ "https://huggingface.co/TheBloke/CodeLlama-7B-Instruct-GGUF/resolve/main/codellama-7b-instruct.Q4_K_M.gguf"
```

---

## Step 3: Verify Download

```bash
python -m kavach.main info
```

This will show ✅ next to any downloaded model.

---

## Air-Gapped Deployment (no internet at all)

For fully air-gapped environments (e.g., forward operating bases):

1. Download the model file on an internet-connected machine
2. Transfer to the air-gapped machine via USB/encrypted media
3. Place in the `models/` directory
4. Run `python -m kavach.main scan <target>` — works completely offline

---

## GPU Acceleration (optional)

If a CUDA GPU is available, llama.cpp will automatically offload model
layers to the GPU for faster inference. No configuration needed —
KAVACH-AIDR auto-detects and uses the GPU.

To manually enable GPU:
```bash
# Reinstall llama-cpp-python with CUDA support
CMAKE_ARGS="-DLLAMA_CUDA=on" pip install llama-cpp-python --force-reinstall
```

---

## Without a Model (graceful degradation)

KAVACH-AIDR works WITHOUT a model download:
- Static analysis (Semgrep + Bandit + Graph) still runs fully
- Findings are still detected, ranked, and reported
- The LLM-powered root-cause analysis and patch generation are skipped
- A static fallback explanation is provided for each finding

**The system never fails to run — it always provides value.**
