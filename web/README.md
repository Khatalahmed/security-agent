# Local Security Agent — Web Console

A thin, polished presentation layer over the existing `security-agent` engine.
It renders **real** scans, findings, source→sink taint graphs, benchmarks and
reports from the engine — nothing is fabricated. Local-only, Ollama-backed.

```
Browser (Next.js) ──▶ FastAPI (../security-agent/webapi) ──▶ security-agent engine ──▶ Ollama
```

## Run locally
Two processes, both local. **1) the API:**
```bash
cd ../security-agent
python -m pip install -r webapi/requirements.txt
python -m uvicorn webapi.app:app --port 8000
```
**2) this UI:**
```bash
cd web
npm install
npm run dev            # http://localhost:3000
```
The UI calls the API at `http://127.0.0.1:8000` by default. Override with
`NEXT_PUBLIC_API_BASE` (this is only the API URL — never a secret or a key).

## Stack
Next.js 16 · TypeScript · Tailwind v4 · lucide-react · Recharts · @xyflow/react
(React Flow, for the source→sink graph). UI primitives are hand-built in a
shadcn-style to avoid extra dependencies.

## Pages
Overview · New Scan · Scans · Findings · Finding detail (source→sink graph +
evidence + human-review actions) · Data Flow · Benchmarks · Reports · Settings.

## Principles honored
- **No second security engine** — all analysis stays in Python; the browser only
  reads results and triggers scans through the engine's CLI.
- **Real data only** — dataflow graphs come from stored taint evidence;
  benchmarks from committed `evaluation/results/*.json`; no fake progress (scan
  stages are parsed from the engine's actual stdout).
- **Local-only / Ollama**; no hosted-LLM provider is introduced by the UI.
- **No secrets in the browser** — `/api/config` returns provider/model only.
- Finding lifecycle actions respect the engine's human-only transitions.
