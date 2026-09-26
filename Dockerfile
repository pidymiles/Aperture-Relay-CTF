FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_ROOT=/data \
    PORT=8080

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo less util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash fieldtech \
    && useradd --system --create-home --shell /usr/sbin/nologin portal \
    && mkdir -p /app/static /data/portal /run/sshd /var/log/aperture

WORKDIR /app
COPY app.py init_challenge.py entrypoint.sh ./
COPY static ./static
COPY sshd_config /etc/ssh/sshd_config
COPY fieldtech-sudoers /etc/sudoers.d/fieldtech

RUN chmod 755 /app/entrypoint.sh \
    && chmod 440 /etc/sudoers.d/fieldtech \
    && chown root:root /etc/sudoers.d/fieldtech

EXPOSE 8080 22

HEALTHCHECK --interval=10s --timeout=3s --start-period=8s --retries=5 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"

ENTRYPOINT ["/app/entrypoint.sh"]
