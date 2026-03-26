FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy app
COPY app.py .
COPY static/ static/

# Azure App Service expects port 8000
EXPOSE 8000

# Production server with gunicorn + uvicorn workers
CMD ["gunicorn", "app:app", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000", "--timeout", "120", "--access-logfile", "-"]
