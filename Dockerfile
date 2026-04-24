# =============================================================================
# ZeroTrust-AI — container image
# =============================================================================
# Minimal image that serves the Streamlit dashboard on :8501.
# Build:   docker build -t zerotrust-ai .
# Run:     docker run -p 8501:8501 --env-file .env zerotrust-ai

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable stdout buffering off for
# clean Docker logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

# Install dependencies first (better layer caching).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project.
COPY . .

EXPOSE 8501

# Liveness: any response on /_stcore/health counts as healthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request, sys; \
r = urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=3); \
sys.exit(0 if r.status == 200 else 1)" || exit 1

CMD ["streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
