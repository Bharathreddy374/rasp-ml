# Backend

See [../docs/BACKEND.md](../docs/BACKEND.md) for the pipeline, API, database schema, model contract and configuration, and [../docs/USAGE.md](../docs/USAGE.md) for how to run it.

```
python -m venv venv && venv\Scripts\python -m pip install -r requirements.txt
venv\Scripts\python train_shadow.py
venv\Scripts\python -m uvicorn app:app --host 0.0.0.0 --port 8000     # needs DATABASE_URL (backend/.env)
venv\Scripts\python -m unittest discover -s tests                      # 70 tests, no database needed
```
