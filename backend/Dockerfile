FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Train at build time so the pickled model always matches the installed scikit-learn.
RUN python -m unittest discover -s tests && python train_shadow.py
# Optional IP data (country / ASN / Tor) for F286-F294 and F340: set GEO_DATA=1 to download it at build.
ARG GEO_DATA=0
RUN if [ "$GEO_DATA" = "1" ]; then python tools/update_geo.py || echo "geo download failed: continuing without"; fi
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
