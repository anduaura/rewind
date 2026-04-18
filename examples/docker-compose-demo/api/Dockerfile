FROM python:3.12-slim
WORKDIR /app
# libfaketime is injected via LD_PRELOAD during `rewind replay` to override the clock.
RUN apt-get update && apt-get install -y --no-install-recommends libfaketime && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
