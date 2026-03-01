FROM python:3.12-slim

WORKDIR /app

# Install curl for health checks (not included in python:3.12-slim)
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Streamlit configuration
RUN mkdir -p /app/.streamlit
COPY config.toml /app/.streamlit/config.toml

EXPOSE 8501

# Health check used by ECS / ALB
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", \
  "--server.port=8501", \
  "--server.address=0.0.0.0", \
  "--server.headless=true", \
  "--browser.gatherUsageStats=false"]
