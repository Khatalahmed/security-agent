# webapi — thin FastAPI layer over the security-agent engine

A **presentation/orchestration** layer only. It imports the existing
`security_agent` package and **never** reimplements analysis, the finding
lifecycle, or safety. The core `security_agent` package stays zero-dependency;
these extra deps (`fastapi`, `uvicorn`) are for this optional layer alone.

## Run (local-only)
```bash
cd security-agent
python -m pip install -r webapi/requirements.txt
python -m uvicorn webapi.app:app --port 8000     # http://127.0.0.1:8000
```
The frontend (../web) expects the API at `http://127.0.0.1:8000`.

## What it does
- Reads the engine's SQLite store (`data/findings.db`) for scans/findings.
- Pings local **Ollama** (`/api/tags`) for status + active model.
- Applies the engine's own lifecycle transitions (`store.transition`,
  human-only `HUMAN_CONFIRMED`/`FALSE_POSITIVE`) — no lifecycle logic duplicated.
- Builds the source->sink **dataflow** graph purely from stored taint
  `evidence.chain`/`sink` (see `dataflow.py`); returns `available:false` truthfully
  for per-file findings with no chain.
- Surfaces **committed** `evaluation/results/*.json` benchmarks (never fabricated)
  and generated `reports/`.
- Launches **real** scans via the CLI subprocess (`jobs.py`) — the engine's own
  controlled interface — and streams its actual progress lines into a truthful
  stage model (no fake percentages).

## Endpoints
`GET /api/health` · `/api/config` · `/api/ollama/status` · `/api/pipeline` ·
`/api/scans` · `/api/scans/{id}` · `/api/scans/{id}/findings` ·
`/api/findings` · `/api/findings/{id}` · `/api/findings/{id}/dataflow` ·
`POST /api/findings/{id}/confirm` · `POST /api/findings/{id}/false-positive` ·
`GET /api/benchmarks` · `/api/reports` · `/api/reports/{name}` ·
`POST /api/scans` (start job) · `GET /api/jobs/{id}`.

## Guarantees
- **Local-only / Ollama** by default; no hosted provider is introduced by this layer.
- **No secrets exposed**: `/api/config` returns provider/model/skills only; API
  keys live in env vars (never in config, never returned).
- Scans go only through the engine CLI; the browser never executes shell commands.
