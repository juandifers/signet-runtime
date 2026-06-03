"""Build the BASELINE and SIGNET pipelines from the same LLM element.

Both pipelines are identical AgentDojo pipelines
``[SystemMessage, InitQuery, llm, ToolsExecutionLoop([executor, llm])]``; the
only difference is the executor inside the loop:
  * baseline -> stock ``ToolsExecutor``
  * signet   -> ``SignetGatedToolsExecutor``

We compose manually (rather than ``from_config``) so we can reuse the exact same
``llm`` instance in both and swap only the executor. The model string is passed
straight to ``OpenAILLM`` / ``AnthropicLLM``, bypassing ``ModelsEnum`` so newer
models (e.g. gpt-5.x) work without the package knowing them.
"""
from __future__ import annotations

import os
from pathlib import Path

from agentdojo.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import (ToolsExecutionLoop,
                                                     ToolsExecutor,
                                                     tool_result_to_str)
from agentdojo.models import MODEL_NAMES

from .gate import SignetGatedToolsExecutor
from .intent_provider import AuthorizedIntentProvider
from .signet_harness import SignetHarness


# ---------------- .env loading (no python-dotenv dependency) ----------------

def load_dotenv(*candidates: str) -> list[str]:
    """Load KEY=VALUE pairs from the first existing .env into os.environ.

    Does not overwrite variables already set in the environment. Returns the
    list of files actually loaded (for logging).
    """
    if not candidates:
        here = Path(__file__).resolve().parent
        candidates = (
            str(here / ".env"),
            str(here.parent.parent / ".env"),   # repo root
        )
    loaded = []
    for path in candidates:
        p = Path(path)
        if not p.is_file():
            continue
        for raw in p.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
        loaded.append(str(p))
    return loaded


# ---------------- provider / model handling ----------------

def detect_provider(model: str) -> str:
    m = model.lower()
    if m.startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
        return "openai"
    if m.startswith("claude"):
        return "anthropic"
    raise ValueError(
        f"Could not infer provider for model '{model}'. Pass --provider openai|anthropic."
    )


def _prose_model_name(provider: str) -> str:
    return {"openai": "GPT-4", "anthropic": "Claude"}.get(provider, "AI assistant")


def register_model_name(model: str, provider: str) -> None:
    """Make the canonical 'important_instructions' attack able to address the model.

    The attack calls ``get_model_name_from_pipeline`` which looks the pipeline
    name up in ``agentdojo.models.MODEL_NAMES``. For models the installed package
    doesn't know (e.g. gpt-5.x) we register a prose name at runtime. This mutates
    a dict; it does not edit or fork the agentdojo source.
    """
    if model not in MODEL_NAMES:
        MODEL_NAMES[model] = _prose_model_name(provider)


def build_llm(model: str, provider: str):
    if provider == "openai":
        import openai
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        return OpenAILLM(openai.OpenAI(), model)
    if provider == "anthropic":
        import anthropic
        from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
        return AnthropicLLM(anthropic.Anthropic(), model)
    raise ValueError(f"Unsupported provider '{provider}'.")


def api_key_present(provider: str) -> bool:
    return bool(os.environ.get(
        {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}[provider]
    ))


# ---------------- pipeline construction ----------------

def build_pipelines(model: str, provider: str, suite,
                    harness: SignetHarness, intent_provider: AuthorizedIntentProvider,
                    provider_label: str = "oracle", mode: str = "strict"):
    """Return (baseline_pipeline, signet_pipeline, gate).

    The two pipelines share the same llm / system-message / init-query elements;
    only the tools executor differs. `intent_provider` is the provider the gate
    ENFORCES; `provider_label` tags its decisions; `mode` selects the gate's binding
    strategy (strict/policy = static-envelope match; predicate = endorsed resolution).
    """
    register_model_name(model, provider)
    llm = build_llm(model, provider)
    system_message = SystemMessage(load_system_message(None))
    init_query = InitQuery()

    baseline_loop = ToolsExecutionLoop([ToolsExecutor(tool_result_to_str), llm])
    baseline = AgentPipeline([system_message, init_query, llm, baseline_loop])
    baseline.name = model

    gate = SignetGatedToolsExecutor(harness, intent_provider, suite,
                                    tool_result_to_str, provider_label=provider_label,
                                    mode=mode)
    signet_loop = ToolsExecutionLoop([gate, llm])
    signet = AgentPipeline([system_message, init_query, llm, signet_loop])
    # Keep the model token in the name so the attack still resolves the prose name.
    signet.name = f"{model}-signet"

    return baseline, signet, gate
