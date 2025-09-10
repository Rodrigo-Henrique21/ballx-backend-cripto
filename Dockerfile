FROM python:3.11-slim


ENV PYTHONDONTWRITEBYTECODE=1 \
PYTHONUNBUFFERED=1 \
PORT=80


WORKDIR /app


# System deps (optional, kept minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
build-essential curl && rm -rf /var/lib/apt/lists/*


COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt


COPY app ./app


EXPOSE 80


HEALTHCHECK --interval=30s --timeout=3s CMD curl -sf http://localhost:${PORT}/healthz || exit 1


CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]