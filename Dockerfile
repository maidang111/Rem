# Rem — orchestration layer for automated security remediation.
# Default command runs the Flask webhook orchestrator (app.py) under gunicorn.
# The one-shot scanner (dependabot_scan.py) can be run by overriding the command:
#   docker run --rm --env-file .env rem python dependabot_scan.py --dry-run
FROM python:3.11-slim

# Don't buffer stdout/stderr (logs show up immediately) and don't write .pyc.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=5000

WORKDIR /app

# Install dependencies first so the layer caches across code-only changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code and prompt templates.
COPY . .

# Run as a non-root user.
RUN useradd --create-home --uid 1000 rem \
    && chown -R rem:rem /app
USER rem

EXPOSE 5000

# Serve the webhook orchestrator. PORT is honored so it matches app.py's default.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 2 --access-logfile - app:app"]
