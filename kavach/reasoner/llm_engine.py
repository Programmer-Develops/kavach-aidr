"""
llm_engine.py — Local LLM inference engine for KAVACH-AIDR.

Wraps llama-cpp-python to run quantized LLMs (Phi-3-mini, CodeLlama)
completely offline on the local machine. Zero internet. Zero foreign API.

Hardware adaptation:
  - Auto-selects GPU layers if CUDA is available
  - Falls back gracefully to CPU-only inference
  - Works even with 4GB RAM (Phi-3-mini-Q4)
"""

import os
from pathlib import Path
from typing import Optional, Generator
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Structured response from the local LLM."""
    text          : str
    tokens_used   : int
    model_name    : str
    finish_reason : str   # "stop" | "length" | "error"


class LLMEngine:
    """
    Local LLM inference engine.

    Uses llama-cpp-python to load a GGUF-format model and run inference
    entirely on the local machine — no network calls, no foreign servers.

    Usage:
        engine = LLMEngine(model_path="models/Phi-3-mini-4k-instruct-q4.gguf")
        engine.load()
        response = engine.generate("Explain this vulnerability: ...")
    """

    def __init__(
        self,
        model_path    : str | Path,
        n_ctx         : int = 4096,
        n_gpu_layers  : int = 0,      # 0 = CPU-only; -1 = all layers on GPU
        n_threads     : int = 4,
        temperature   : float = 0.1,
        max_tokens    : int = 1024,
        verbose       : bool = False,
    ):
        self.model_path   = Path(model_path)
        self.n_ctx        = n_ctx
        self.n_gpu_layers = n_gpu_layers
        self.n_threads    = n_threads
        self.temperature  = temperature
        self.max_tokens   = max_tokens
        self.verbose      = verbose
        self._llm         = None
        self._loaded      = False

    def load(self) -> None:
        """
        Load the GGUF model into memory.
        Call this once before calling generate().
        Raises FileNotFoundError if the model file doesn't exist.
        """
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model not found: {self.model_path}\n"
                f"→ Run:  python -m kavach.scripts.download_model\n"
                f"  or see models/DOWNLOAD.md for manual instructions."
            )

        try:
            from llama_cpp import Llama
        except ImportError:
            raise ImportError(
                "llama-cpp-python not installed.\n"
                "Install with: pip install llama-cpp-python\n"
                "For GPU (CUDA): CMAKE_ARGS='-DLLAMA_CUDA=on' pip install llama-cpp-python"
            )

        self._llm = Llama(
            model_path   = str(self.model_path),
            n_ctx        = self.n_ctx,
            n_gpu_layers = self.n_gpu_layers,
            n_threads    = self.n_threads,
            verbose      = self.verbose,
        )
        self._loaded = True

    def generate(
        self,
        prompt        : str,
        system_prompt : Optional[str] = None,
        max_tokens    : Optional[int] = None,
        temperature   : Optional[float] = None,
        stop          : Optional[list[str]] = None,
    ) -> LLMResponse:
        """
        Run inference on a prompt and return the LLM's response.

        Args:
            prompt        : The user message / query.
            system_prompt : Optional system instruction prepended to the prompt.
            max_tokens    : Override the default max token count.
            temperature   : Override the default temperature.
            stop          : List of stop strings.

        Returns:
            LLMResponse with the generated text and metadata.
        """
        if not self._loaded or self._llm is None:
            raise RuntimeError("LLM not loaded. Call engine.load() first.")

        mt   = max_tokens  or self.max_tokens
        temp = temperature or self.temperature

        # ── Build messages (chat-style, works with all instruction-tuned models)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            raw = self._llm.create_chat_completion(
                messages    = messages,
                max_tokens  = mt,
                temperature = temp,
                stop        = stop or ["</s>", "<|end|>", "<|im_end|>"],
            )
            choice        = raw["choices"][0]
            text          = choice["message"]["content"].strip()
            finish_reason = choice.get("finish_reason", "stop")
            tokens_used   = raw.get("usage", {}).get("total_tokens", 0)

        except Exception as e:
            return LLMResponse(
                text          = f"[LLM ERROR: {e}]",
                tokens_used   = 0,
                model_name    = str(self.model_path.name),
                finish_reason = "error",
            )

        return LLMResponse(
            text          = text,
            tokens_used   = tokens_used,
            model_name    = self.model_path.name,
            finish_reason = finish_reason,
        )

    def is_loaded(self) -> bool:
        return self._loaded

    def unload(self) -> None:
        """Free model memory."""
        self._llm    = None
        self._loaded = False

    def __repr__(self) -> str:
        status = "loaded" if self._loaded else "not loaded"
        return f"LLMEngine(model={self.model_path.name}, status={status})"


# ── Singleton factory ────────────────────────────────────────────────────────

_engine_instance: Optional[LLMEngine] = None


def get_engine(config=None) -> Optional[LLMEngine]:
    """
    Get or create the global LLMEngine singleton.

    Returns None if the model file doesn't exist (graceful degradation —
    the pipeline still runs static analysis without the LLM).

    Args:
        config: KavachConfig (from kavach.config.build_config)
    """
    global _engine_instance

    if _engine_instance is not None and _engine_instance.is_loaded():
        return _engine_instance

    if config is None:
        return None

    if config.model_path is None or not config.model_path.exists():
        return None   # Model not downloaded yet — degrade gracefully

    engine = LLMEngine(
        model_path   = config.model_path,
        n_ctx        = config.n_ctx,
        n_gpu_layers = config.n_gpu_layers,
        n_threads    = config.n_threads,
        temperature  = config.temperature,
        max_tokens   = config.max_tokens,
        verbose      = config.verbose,
    )
    engine.load()
    _engine_instance = engine
    return engine
