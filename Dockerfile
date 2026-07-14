FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/fetch_mihomo.sh scripts/fetch_mihomo.sh
RUN chmod +x scripts/fetch_mihomo.sh \
    && scripts/fetch_mihomo.sh /usr/local/bin/mihomo

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium

COPY main.py .
COPY clash_probe.py .
COPY cli.py .
COPY static ./static

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
