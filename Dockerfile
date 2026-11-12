# RiskPrism. Standard library only; the Azure SDK is optional. See "Run with Docker" in the README.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENTROPY_HOST=0.0.0.0 \
    ENTROPY_PORT=8765 \
    ENTROPY_DATA_DIR=/data

# Uncomment to store evidence in Azure Blob (managed identity or account URL).
# RUN pip install --no-cache-dir azure-storage-blob azure-identity

RUN useradd --system --create-home --uid 10001 entropy && mkdir /data && chown entropy /data
WORKDIR /app
COPY --chown=entropy . /app
USER entropy

VOLUME ["/data"]
EXPOSE 8765

# The container binds 0.0.0.0, so the server refuses to start unless ENTROPY_AUTH is
# accounts, password or easyauth. Use accounts for a team (see the README).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('ENTROPY_PORT','8765'),timeout=4)"

CMD ["python", "serve.py"]
