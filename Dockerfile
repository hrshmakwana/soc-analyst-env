FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (cacheable layer)
COPY server/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Copy all environment code
COPY models.py /app/models.py
COPY __init__.py /app/__init__.py
COPY client.py /app/client.py
COPY openenv.yaml /app/openenv.yaml
COPY pyproject.toml /app/pyproject.toml
COPY README.md /app/README.md
COPY data/ /app/data/
COPY server/ /app/server/

# Copy inference script (for reference / validation)
COPY inference.py /app/inference.py

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

# Expose port (HF Spaces standard)
EXPOSE 7860

# Run server — HF Spaces expects the app to listen on 7860
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
