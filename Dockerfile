# CDF Manager — nginx + proxy.py in a single container, mirroring the
# geonosis bare-metal deployment (see README.md's Docker section for
# required environment variables and the /data volume).

FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

WORKDIR /app

# proxy.py is stdlib-only — no pip install needed.
COPY proxy.py                  /app/proxy.py
COPY cdf-manager.html          /app/static/cdf-manager.html
COPY docker/generate_config.py /app/docker/generate_config.py
COPY docker/nginx.conf         /etc/nginx/sites-enabled/cdf-manager
COPY docker/entrypoint.sh      /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/docker/generate_config.py

# Bind-mount a host directory here to persist config.py (admin credentials,
# generated on first boot from env vars) and the app's runtime state
# (state.json, users.json, sessions.json, settings.json).
VOLUME /data

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost/health', timeout=3)" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
