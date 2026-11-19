FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 iptables iw wireless-tools aircrack-ng \
      nmap tcpdump net-tools dnsutils procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-real.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements-real.txt

COPY app ./app
COPY sentinelip.py ./sentinelip.py

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/status', timeout=5)"

CMD ["python", "sentinelip.py", "--host", "0.0.0.0", "--port", "8000"]
