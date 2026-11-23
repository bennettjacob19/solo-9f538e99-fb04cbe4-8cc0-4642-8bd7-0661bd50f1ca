FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KEYSTORE_DIR=/data/keystore \
    VOLUME_DIR=/data/volumes

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backup_app ./backup_app

# keystore (master keys + metadata DB) and backup ciphertexts are separate
# volumes; the application creates the mount points itself.
RUN mkdir -p /data/keystore /data/volumes && chmod 700 /data/keystore

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

CMD ["python", "-m", "backup_app.wsgi"]
