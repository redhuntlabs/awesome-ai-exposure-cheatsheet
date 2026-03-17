# AI Exposure Cheatsheet

![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![Linkedin Badge](https://img.shields.io/badge/LinkedIn-redhunt%20labs-blue?style=plastic-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/redhunt-labs/)
[![Twitter Badge](https://img.shields.io/badge/-redHuntLabs-black?style=plastic-square&logo=x&logoColor=white&link=https://twitter.com/redHuntLabs)](https://twitter.com/redHuntLabs)

A community-driven reference for discovering **exposed AI infrastructure** across the modern AI stack. This resource maps the attack surface of publicly exposed AI systems, from leaked API keys to unprotected inference servers, agent orchestrators, and vector databases.

This research was first presented at **Nullcon Goa 2026** in the talk *"No CVE for That: Invisible Breach Path from AI Leftovers"* and is now being made public. Slides: [slideshare.net](https://www.slideshare.net/slideshow/no-cve-for-that-ai-exposures-explained/286453463)

> **Intended Use:** Security research, bug bounty, authorized pentesting, and defensive monitoring. Always obtain proper authorization before probing systems you do not own.

---

## Table of Contents

- [Stack Architecture](#stack-architecture)
- [Layer 0: Identity & Access (API Keys)](#layer-0-identity--access-api-keys)
- [Layer 1: Inference Layer (Runtime Plane)](#layer-1-inference-layer-runtime-plane)
- [Layer 2: Orchestration, Agents & Chat UIs](#layer-2-orchestration-agents--chat-uis)
- [Layer 3: Data & Memory Layer (RAG / Embeddings)](#layer-3-data--memory-layer-rag--embeddings)
- [Layer 4: ML Engineering & Experimentation](#layer-4-ml-engineering--experimentation)
- [Layer 5: LLM Gateways & Observability](#layer-5-llm-gateways--observability)
- [Layer 6: Model Hubs, Plugins & MCP](#layer-6-model-hubs-plugins--mcp)
- [Layer 7: Public Chats](#layer-7-public-chats)
- [Layer 8: Miscellaneous AI Dev Surfaces](#layer-8-miscellaneous-ai-dev-surfaces)
- [Contributing](#contributing)
- [Credits](#credits)

---

## Stack Architecture

The AI stack is broken down into layers, each with its own exposure surface. Use the table below to navigate to the relevant layer.

| Layer | Name | Examples |
|---|---|---|
| 0 | Identity & Access | API keys for OpenAI, Anthropic, Groq... |
| 1 | Inference (Runtime Plane) | Ollama, llama.cpp, LM Studio |
| 2 | Orchestration, Agents & Chat UIs | Flowise, n8n, Dify, Open WebUI, LibreChat |
| 3 | Data & Memory (RAG / Embeddings) | Chroma, Qdrant, Weaviate, Milvus |
| 4 | ML Engineering & Experimentation | MLflow, Ray, Label Studio, ClearML |
| 5 | LLM Gateways & Observability | LiteLLM, Kong, Langfuse, LangSmith |
| 6 | Model Hubs, Plugins & MCP | Hugging Face, MCP servers, ModelScope |
| 7 | Public Chats | ChatGPT shares, Claude shares, Gemini shares |
| 8 | Miscellaneous AI Dev Surfaces | Gradio, Streamlit, Chainlit, Jupyter |

---

## Layer 0: Identity & Access (API Keys)

Leaked API keys for AI providers found in public code repositories, config files, and paste sites. Regex patterns below can be used in open source secret scanning tools.

| Provider | Regex Pattern | Notes |
|---|---|---|
| **Hugging Face** | `\b(?:hf_\|api_org_)[a-zA-Z0-9]{34}\b` | Both user tokens and org API keys |
| **OpenAI** | `\b(sk-(?:(?:proj\|svcacct\|service)-[A-Za-z0-9_-]+\|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+)\b` | Standard keys |
| | `\b(sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58})\b` | Admin keys |
| | `\b(sk-[A-Z0-9]{48})\b` | Legacy format |
| **Anthropic** | `\b(sk-ant-(?:admin01\|api03)-[\w\-]{93}AA)\b` | |
| **Google Gemini** | `\b(AIzaSy[A-Za-z0-9_-]{33})\b` | Requires API call to confirm scope; generic GCP key format |
| **xAI (Grok)** | `\b(xai-[0-9a-zA-Z_]{80})\b` | |
| **Groq** | `\b(gsk_[a-zA-Z0-9]{52})\b` | |
| **NVIDIA (NIM / NVAI)** | `\b(nvapi-[a-zA-Z0-9_-]{64})\b` | |
| **Perplexity** | `\b(pplx-[A-Za-z0-9]{48})\b` | |
| **ElevenLabs** | `\b((?:sk)_[a-f0-9]{48})\b` | |
| **Stability AI** | `\b(sk-[A-Za-z0-9]{48})\b` | Overlaps with other `sk-` prefixed keys; use context |
| **DeepSeek** | `\b(sk-[a-z0-9]{32})\b` | Short format; overlaps with other providers, needs context |
| **Cerebras AI** | `(?i)\b(csk-[a-z0-9]{48})\b` | |
| **ZHIPU / BigModel** | `(?i)\b([A-F0-9]{32}\.[A-Z0-9]{16})\b` | |
| **Langfuse** | `\b(pk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b` | Public key |
| | `\b(sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b` | Secret key |
| **LangSmith** | `\b(lsv2_(?:pt\|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b` | |
| **Azure OpenAI** | `(?i)([a-z0-9-]+\.openai\.azure\.com)` | Host pattern; key itself is generic, needs endpoint context |
| **AWS Bedrock** | AWS access key + secret | Standard AWS credentials; enumerate Bedrock permissions separately |
| **Clarifai** | - | Generic format; no distinct pattern yet |
| **AssemblyAI** | - | Generic format; no distinct pattern yet |
| **Weights & Biases** | - | Generic format; no distinct pattern yet |

---

## Layer 1: Inference Layer (Runtime Plane)

Directly exposed LLM inference servers, often running without authentication.

| Tool | Fingerprint | Shodan Queries |
|---|---|---|
| **Ollama** | `GET /` body contains `"Ollama is running"` | `http.html:"Ollama is running"` <br> `product:"Ollama"` |
| **llama.cpp** | `GET /` body contains `"Owned By: llamacpp"` OR `Server` header contains `"llama.cpp"` | `"server: llama.cpp"` <br> `"Owned By: llamacpp"` <br> `product:"llama.cpp"` |
| **LM Studio** | `GET /` body contains `"Unexpected endpoint or method. (GET /)"` AND `GET /api/v0/models` returns `200 OK` | `http.html:"Unexpected endpoint or method. (GET /)"` |
| **OpenAI-compatible servers** (generic) | Probe `/openapi.json` or `/api/v0/models` to identify the underlying server | `port:8000 "server: uvicorn" "404 Not Found"` |

---

## Layer 2: Orchestration, Agents & Chat UIs

Self-hosted agent frameworks and chat interfaces, often exposing credentials, system prompts, and connected tools.

| Tool | Fingerprint | Shodan Queries |
|---|---|---|
| **OpenClaw** | `GET /` title is `"Clawdbot Control"` OR `"Moltbot Control"` OR `"OpenClaw Control"` | `http.title:"Clawdbot Control","Moltbot Control","OpenClaw Control"` |
| **n8n** | favicon hash `-831756631` OR `-670975485` OR body contains `"n8n:config:sentry"` | `http.favicon.hash:-831756631` <br> `http.favicon.hash:-670975485` <br> `http.html:"n8n:config:sentry"` |
| **Flowise** | `GET /` body contains `"Flowise - Build AI Agents, Visually"` | `http.html:"Flowise - Build AI Agents, Visually"` |
| **Open WebUI** | body contains `"open-webui"` OR favicon hash `1239683376` | `http.html:"open-webui"` <br> `http.favicon.hash:1239683376` |
| **Dify** | favicon hash `97378986` | `http.favicon.hash:97378986` |
| **AnythingLLM** | body contains `"<title >AnythingLLM \| Your personal LLM trained on anything</title>"` OR favicon hash `-1279687529` | `http.html:"<title >AnythingLLM \| Your personal LLM trained on anything</title>"` <br> `http.favicon.hash:-1279687529` |
| **Onyx** | `GET /` body contains `"<title>Onyx</title>"` | `http.html:"<title>Onyx</title>"` |
| **LibreChat** | `GET /` body contains `"LibreChat"` | `http.html:"LibreChat"` |
| **LobeChat** | `GET /` body contains `"<title>LobeChat</title>"` | `http.html:"<title>LobeChat</title>"` |
| **LobeHub** | `GET /` body contains `"<title>LobeHub · Agent teammates that grow with you</title>"` | `http.html:"<title>LobeHub · Agent teammates that grow with you</title>"` |
| **SillyTavern** | `GET /` body contains `"SillyTavern"` | `http.html:"SillyTavern"` |
| **AstrBot** | `GET /` body contains `"<title>AstrBot - 仪表盘</title>"` | `http.html:"<title>AstrBot - 仪表盘</title>"` |
| **LocalAI** | `GET /` body contains `"<title>LocalAI"` | `http.html:"<title>LocalAI"` |
| **ChatGPT Next Web** | `GET /` body contains `"<title>ChatGPT Next Web</title>"` | `http.html:"<title>ChatGPT Next Web</title>"` |
| **Better ChatGPT** | `GET /` body contains `"Better ChatGPT"` | `http.html:"Better ChatGPT"` |

---

## Layer 3: Data & Memory Layer (RAG / Embeddings)

Exposed vector databases and embedding stores, may contain sensitive documents, embeddings, and full RAG corpora.

| Tool | Fingerprint | Shodan Queries |
|---|---|---|
| **Chroma** | `GET /` has `chroma-trace-id` response header OR `GET /api/v1/heartbeat` + `GET /api/v1/collections` return `200 OK` | `product:"Chroma"` <br> `chroma-trace-id:` <br> `port:8000 "server: uvicorn" "404 Not Found"` (probe further) |
| **Weaviate** | `GET /` body contains `"https://weaviate.io/"` | `http.html:"https://weaviate.io"` |
| **Vespa** | favicon hash `543917977` | `http.favicon.hash:543917977` |
| **Milvus (Attu UI)** | `GET /` body contains `"<title>Attu</title>"` | `"Milvus Attu Web Interface"` <br> `product:"Milvus Attu Web Interface"` <br> `html:"<title>Attu</title>"` |
| **Qdrant** | `GET /` body contains `"qdrant - vector search engine"` | `http.html:"qdrant - vector search engine"` |

---

## Layer 4: ML Engineering & Experimentation

Exposed experiment trackers, distributed training dashboards, and labeling platforms.

| Tool | Fingerprint | Shodan Queries |
|---|---|---|
| **Ray (Anyscale)** | body contains `"<title>Ray Dashboard</title>"` OR favicon hash `463802404` | `http.html:"<title>Ray Dashboard</title>"` <br> `http.favicon.hash:463802404` |
| **MLflow** | body contains `"<title>MLflow</title>"` OR favicon hash `-1507094812` | `http.html:"<title>MLflow</title>"` <br> `http.favicon.hash:-1507094812` |
| **Label Studio** | body contains `"<title>Label Studio</title>"` OR favicon hash `-1649949475` OR `1557941012` | `http.html:"<title>Label Studio</title>"` <br> `http.favicon.hash:-1649949475` <br> `http.favicon.hash:1557941012` |
| **ClearML** | body contains `"<title>Sign up/login to ClearML to automate and orchestrate your ML stack</title>"` OR favicon hash `1356614944` | `http.html:"<title>Sign up/login to ClearML to automate and orchestrate your ML stack</title>"` <br> `http.favicon.hash:1356614944` |

---

## Layer 5: LLM Gateways & Observability

Exposed LLM proxy/gateway servers and observability platforms, may expose API key configurations, usage data, and routing rules.

| Tool | Fingerprint | Shodan Queries |
|---|---|---|
| **LiteLLM** | `GET /` body contains `"<title>LiteLLM API - Swagger UI</title>"` | `http.html:"<title>LiteLLM API - Swagger UI</title>"` |
| **Kong** | body contains `"<title>Kong Manager OSS</title>"` OR favicon hash `-112038367` OR `Server: kong/` header OR `X-Kong-Response-Latency` / `X-Kong-Admin-Latency` headers | `http.html:"<title>Kong Manager OSS</title>"` <br> `http.favicon.hash:-112038367` <br> `Server: kong/` <br> `X-Kong-Response-Latency` <br> `X-Kong-Admin-Latency` |
| **Portkey Gateway** | `GET /` body contains `"AI Gateway says hey!"`, then probe `/public/` | `http.html:"AI Gateway says hey!"` |
| **Langfuse** | `GET /` body contains `"LangfuseIcon"` | `http.html:"LangfuseIcon"` |
| **LangSmith** | `GET /` body contains `"<title>LangSmith</title>"` | `http.html:"<title>LangSmith</title>"` |
| **Arize Phoenix** | favicon hash `-1338105374` | `http.favicon.hash:-1338105374` |

---

## Layer 6: Model Hubs, Plugins & MCP

Discovery surfaces for Model Context Protocol (MCP) servers, model registries, and AI plugin marketplaces.

### MCP Servers (Model Context Protocol)

| Surface | Query |
|---|---|
| **Shodan** | `"Model Context Protocol"` |
| **GitHub - package.json** | `"@modelcontextprotocol/" in:package.json` |
| **GitHub - requirements.txt** | `"fastmcp" in:requirements.txt` |
| **NPM** | `keywords:modelcontextprotocol` · `keywords:mcp` |
| **MCP Registry** | registry.modelcontextprotocol.io |

### Model Hubs & Plugin Marketplaces

| Platform | URL |
|---|---|
| **Hugging Face** | huggingface.co |
| **ModelScope** | modelscope.cn |
| **ClaWHub (OpenClaw skills)** | clawhub.ai |

---

## Layer 7: Public Chats

AI chat conversations inadvertently shared publicly via platform share links. Indexed by search engines and web archives.

| Platform | URL Pattern | Discovery Queries |
|---|---|---|
| **ChatGPT** | `chatgpt.com/share/*` | [Wayback Machine](https://web.archive.org/web/*/https://chatgpt.com/share/*) |
| **Claude** | `claude.ai/share/*` | [Wayback Machine](https://web.archive.org/web/*/https://claude.ai/share/*) |
| **Gemini** | `gemini.google.com/share/*` | DuckDuckGo: `site:gemini.google.com/share/` · [Wayback Machine](https://web.archive.org/web/*/https://gemini.google.com/share/*) |
| **Together AI** | `chat.together.ai/s/*` | [Google](https://www.google.com/search?q=inurl:chat.together.ai/s/+site:chat.together.ai) · [Brave](https://search.brave.com/search?q=site%3Achat.together.ai+%22%2Fs%2F%22&source=web) · [Bing](https://www.bing.com/search?q=domain:chat.together.ai/s/) · [Wayback Machine](https://web.archive.org/web/*/https://chat.together.ai/s/*) |
| **z.ai** | `chat.z.ai/s/*` | [Google](https://www.google.com/search?q=inurl:chat.z.ai/s/+site:chat.z.ai) · [Brave](https://search.brave.com/search?q=site%3Achat.z.ai%2Fs%2F&source=web) · [Wayback Machine](https://web.archive.org/web/*/https://chat.z.ai/s/*) |
| **Kimi** | `www.kimi.com/share/*` | [Bing](https://www.bing.com/search?q=domain:www.kimi.com/share/) · [Brave](https://search.brave.com/search?q=site%3Awww.kimi.com%2Fshare%2F&source=web) · [Wayback Machine](https://web.archive.org/web/*/https://www.kimi.com/share/*) |
| **Manus** | `manus.im/share/*` | [Brave](https://search.brave.com/search?q=site%3Amanus.im%2Fshare%2F&source=web) · DuckDuckGo: `site:manus.im/share/` · [Wayback Machine](https://web.archive.org/web/*/https://manus.im/share/*) |

---

## Layer 8: Miscellaneous AI Dev Surfaces

Commonly exposed AI development and demo frameworks.

| Tool | Fingerprint | Shodan Queries |
|---|---|---|
| **Gradio** | `GET /` body contains `"gradio-app"` | `http.html:"gradio-app"` |
| **Streamlit** | `GET /` body contains `"streamlit"` | `http.title:"streamlit"` |
| **Chainlit** | `GET /` body contains `"Chainlit/chainlit"` | `http.html:"Chainlit/chainlit"` |
| **Google ADK Dev UI** | `GET /` body contains `"Agent Development Kit Dev UI"` | `http.html:"Agent Development Kit Dev UI"` |
| **Jupyter Notebook / Lab** | Page title `"Jupyter Notebook"` or `"JupyterLab"` | `http.title:"Jupyter Notebook"` <br> `http.title:"JupyterLab"` |

### No-Code AI App Builders

Apps generated by no-code AI SaaS platforms are deployed to predictable subdomain patterns, making them enumerable via DNS bruteforce, certificate transparency logs, and open source tools.

| Platform | Subdomain Pattern |
|---|---|
| **v0.dev** | `v0-*.vercel.app` |
| **Lovable** | `*.lovable.app` |
| **Create.xyz** | `*.created.app` |
| **Trickle** | `*.trickle.host` |
| **Capacity** | `*.capacity.studio` |
| **Instance** | `*.instance.app` |
| **Getcreatr** | `*.getcreatr.xyz` |
| **Base44** | `*.base44.app` |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to add new findings.

---

## Credits

Regex patterns for API key detection are built on community research. Special thanks to:
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
- [mongodb/kingfisher](https://github.com/mongodb/kingfisher)

---

> Maintained by [RedHunt Labs](https://redhuntlabs.com/)
