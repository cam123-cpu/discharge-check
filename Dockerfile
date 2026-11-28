# syntax=docker/dockerfile:1
#
# Discharge Check: production-style image.
#
#   docker build -t discharge-check .
#   docker run --rm -p 127.0.0.1:8000:8000 --env-file .env \
#     --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
#     -v discharge-data:/data discharge-check
#
# No secrets are baked in. DATA_KEY, SESSION_PEPPER (and optionally
# ANTHROPIC_API_KEY, AUDIT_KEY) come from the environment at run time
# (ECS task definition secrets, `--env-file`, compose `env_file`).
#
# Base image: exact Python patch + Debian release, pinned by digest so a
# rebuild is reproducible. Dependabot (docker ecosystem) proposes updates.
# The digest is the multi-arch index digest of python:3.13.18-slim-trixie.
ARG PYTHON_IMAGE=python:3.13.18-slim-trixie@sha256:168d3a5d10f2152f8e8d77b6843ac82c22a846cfefeef7afdf9aa630404e82a7

# ---------- builder: resolve runtime dependencies into a venv ----------
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv
# Runtime requirements only; pytest, httpx and pip-audit stay out of the image.
COPY requirements.txt /tmp/requirements.txt
# pip is not needed at run time; it is removed from the venv afterwards.
RUN /opt/venv/bin/pip install --no-cache-dir --require-virtualenv -r /tmp/requirements.txt \
    && /opt/venv/bin/python -m pip uninstall --yes pip

# ---------- runtime ----------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="discharge-check" \
      org.opencontainers.image.description="Discharge record compliance checker (prototype; synthetic data only)" \
      org.opencontainers.image.source="https://github.com/cam123-cpu/discharge-check"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    # SQLite lives on the /data volume, the only writable path besides /tmp.
    DATABASE_PATH=/data/app.db \
    # Read by uvicorn itself for --proxy-headers. Keep 127.0.0.1 (the
    # HEALTHCHECK below relies on it) and append the load balancer's subnet
    # CIDRs at deploy time, e.g. "127.0.0.1,10.0.0.0/16". Never use "*".
    FORWARDED_ALLOW_IPS=127.0.0.1

# 1. Apply Debian security updates published after the base image was built
#    (Trivy flags them otherwise; the digest pin alone would freeze them).
# 2. Remove the base image's own pip and its bundled wheel: the app runs from
#    /opt/venv, and pip vendors urllib3/msgpack/pkg_resources copies that
#    scanners report and an attacker could use to install code.
# 3. Fixed, non-root UID/GID so volume ownership is predictable (EFS access
#    points, Kubernetes runAsUser). No login shell, no home directory.
# hadolint ignore=DL3005
RUN apt-get update --error-on=any \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.*/ensurepip/_bundled /usr/local/bin/pip* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin app \
    && install -d -o 10001 -g 10001 -m 0700 /data

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# Only what runs: the app package (code, rules.json, templates, static),
# the setup/seed scripts and the synthetic samples the seed loads.
# Files stay root-owned and read-only to the app user.
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY samples/ ./samples/
# Byte-compile at build time; the root filesystem is read-only at run time.
RUN python -m compileall -q app scripts

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000

# Python instead of curl (none in the image). http.client does not follow
# redirects, so a 308 from FORCE_HTTPS counts as unhealthy rather than hiding.
# The app answers /healthz before the host check and HTTPS redirect (so load
# balancer probes by task IP work); the headers below keep this probe working
# even if that exemption is ever removed:
# - Host: first ALLOWED_HOSTS entry, so TrustedHostMiddleware accepts it
#   (a leading "*." wildcard becomes "healthcheck.").
# - X-Forwarded-Proto: https, trusted only because 127.0.0.1 is in
#   FORWARDED_ALLOW_IPS, so FORCE_HTTPS=1 does not redirect the probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,sys,http.client as h\nhost=(os.environ.get('ALLOWED_HOSTS','').split(',')[0].strip() or 'localhost')\nhost='localhost' if host=='*' else host.replace('*.','healthcheck.',1)\nc=h.HTTPConnection('127.0.0.1',8000,timeout=4)\nc.request('GET','/healthz',headers={'Host':host,'X-Forwarded-Proto':'https'})\nsys.exit(0 if c.getresponse().status==200 else 1)"]

CMD ["uvicorn", "app.main:get_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header", "--proxy-headers"]
