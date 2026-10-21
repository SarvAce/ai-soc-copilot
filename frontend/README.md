# React + TypeScript interface

Replaces nothing: the Streamlit app keeps running alongside it.

```bash
# 1. adapter (repo root): FastAPI + SSE over the existing pipeline, no changes to core/agents/graph
.venv/bin/pip install -r requirements-api.txt
.venv/bin/python -m uvicorn soc_copilot.api.app:app --port 8000

# 2. frontend
cd frontend && npm install && npm run dev      # http://localhost:5173 (proxies /api -> :8000)
```

Runs live in an in-memory checkpointer, so a paused case does not survive an adapter restart.
The narrative, `user_agent` and raw log lines are always rendered as React text nodes (check R10).
