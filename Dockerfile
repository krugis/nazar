# Nazar container image. Usage (host network so 127.0.0.1 reaches LAPI and Ollama):
#   docker build -t nazar .
#   docker run -d --name nazar --network host \
#     -v /etc/nazar:/etc/nazar:ro -v nazar-data:/var/lib/nazar nazar
# Create /etc/nazar first with `nazar init` on the host, or by hand (docs/install.md).

FROM python:3.12-slim-bookworm AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE THIRD_PARTY_LICENSES.md ./
COPY src ./src
COPY prompts ./prompts
COPY examples ./examples
COPY deploy ./deploy
RUN python -m venv /opt/nazar \
 && /opt/nazar/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/nazar/bin/pip install --no-cache-dir .

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.title="nazar" \
      org.opencontainers.image.description="AI-assisted protection for Linux servers, built on CrowdSec" \
      org.opencontainers.image.source="https://github.com/krugis/nazar" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 nazar \
 && useradd --system --uid 10001 --gid nazar --home-dir /var/lib/nazar --shell /usr/sbin/nologin nazar \
 && mkdir -p /var/lib/nazar /etc/nazar && chown nazar:nazar /var/lib/nazar
COPY --from=build /opt/nazar /opt/nazar
ENV PATH="/opt/nazar/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER nazar
VOLUME ["/var/lib/nazar"]
ENTRYPOINT ["nazar"]
CMD ["run"]
