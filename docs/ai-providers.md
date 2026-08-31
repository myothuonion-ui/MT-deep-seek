# MT Pentester AI providers

MT Pentester has one provider-neutral connector. Select a direct provider or a
LiteLLM gateway with `AI_PROVIDER`; do not reuse one provider's key variable for
another provider.

| Provider | `AI_PROVIDER` | Key variable | Model variable |
|---|---|---|---|
| Ollama | `local` | none | `OLLAMA_MODEL` |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` | `DEEPSEEK_MODEL` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `OPENROUTER_MODEL` |
| NVIDIA NIM | `nvidia_nim` | `NVIDIA_NIM_API_KEY` | `NVIDIA_NIM_MODEL` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` | `GEMINI_MODEL` |
| LiteLLM | `litellm` | `LITELLM_MASTER_KEY` | `LITELLM_MODEL` |

## Secret handling

- Commit only `.env.example`, never `.env`.
- The settings UI can inject a key into the current backend process but does not
  persist it. Restart-safe deployments must use environment variables, Docker
  secrets, or a dedicated secret manager.
- Provider metadata endpoints return only configuration status, never key values.
- Logs and reports must not contain authorization headers or credentials.

## LiteLLM gateway

`deploy/litellm-config.yaml` defines stable role aliases. Run the gateway as a
separate service, inject only the provider keys it needs, and point MT Pentester
to it with:

```env
AI_PROVIDER=litellm
LITELLM_API_BASE=http://localhost:4000/v1
LITELLM_MASTER_KEY=sk-your-private-gateway-key
LITELLM_MODEL=planner-strong
```

Keep automatic fallback conservative. A failed model call must never cause a
pentest action to execute twice; retries apply only to model inference, not tool
execution.
