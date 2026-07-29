FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Prowler is an executable dependency, not a library Enkstein imports. It is
# installed into its own virtual environment so its large transitive
# dependency tree cannot conflict with the backend's pinned requirements.
# Enkstein resolves it at /opt/prowler-venv/bin/prowler and reports it as
# unavailable rather than failing when the image is built without it.
ARG PROWLER_VERSION=5.36.0
RUN python -m venv /opt/prowler-venv && \
    /opt/prowler-venv/bin/pip install --no-cache-dir "prowler==${PROWLER_VERSION}" && \
    /opt/prowler-venv/bin/prowler --version

# Copy source
COPY . .

EXPOSE 8000

# Copy & make entrypoint executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
