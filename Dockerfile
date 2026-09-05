# The DNS Guard control plane.
#
# Serves the policy/feeds/analytics/evidence API. The scanner runs from the same
# image (python3 tools/scan.py), so a container can be used either way, but the
# default command is the API because that is the long-running process.
FROM python:3.11-slim

WORKDIR /app

# dnsutils is for operator debugging inside the container; the scanner resolves
# through dnspython, not through these binaries.
RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils traceroute \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dnsguard ./dnsguard
COPY module_framework ./module_framework
COPY tools ./tools

# Documents live here when DNSGUARD_DATA_DIR points at it; empty by default, in
# which case the API runs against an in-memory store.
RUN mkdir -p /data && useradd --system --uid 10001 dnsguard && chown -R dnsguard /app /data
USER dnsguard

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DNSGUARD_DATA_DIR=/data

EXPOSE 8000

# DNSGUARD_API_TOKEN must be supplied at run time. The app refuses to start
# without it rather than coming up unauthenticated.
CMD ["python", "-c", "import uvicorn; from dnsguard.api import create_app; uvicorn.run(create_app(), host='0.0.0.0', port=8000)"]
