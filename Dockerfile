# Multi-stage non-root container for vuln-mitigation-analyst
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md /app/
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY src /app/src
RUN uv pip install --no-cache-dir .

# Runtime stage
FROM python:3.12-slim-bookworm AS runtime

# Install system dependencies (dpkg is built-in)
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user (UID 1005) in group oakai (GID 2000)
RUN groupadd -g 2000 oakai && \
    useradd -u 1005 -g oakai -s /bin/false -m vuln-mitigator

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV UDS_MITIGATE_SOCKET="/run/oakai/mitigate.sock"
ENV UDS_APPROVE_SOCKET="/run/oakai/approve.sock"
ENV FALCO_RULES_DIR="/etc/falco/rules.d"

# Pre-create socket and rules directories with group permissions
RUN mkdir -p /run/oakai /etc/falco/rules.d && \
    chown -R vuln-mitigator:oakai /run/oakai /etc/falco/rules.d && \
    chmod 770 /run/oakai /etc/falco/rules.d

USER vuln-mitigator:oakai
ENTRYPOINT ["vuln-mitigation-analyst"]
CMD ["serve"]
