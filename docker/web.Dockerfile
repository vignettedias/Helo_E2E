# ---------------------------------------------------------------------------
# Helo web client -- multi-stage build.
#
# Stage 1 compiles the Flutter web app; stage 2 serves the static files with
# Caddy. The image holds no keys and no user data: every key is generated in
# the visitor's browser and never leaves it. Its job is to deliver the client
# code intact, so it is built reproducibly from a pinned, checksummed SDK.
# ---------------------------------------------------------------------------

# --- Stage 1: build --------------------------------------------------------
FROM debian:bookworm-slim AS build

ARG FLUTTER_VERSION=3.47.7
ARG FLUTTER_SHA256=af7455f540df951184c7953fbe3cf884766e7541dacf8571f9f582db03dd6230

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git unzip xz-utils \
 && rm -rf /var/lib/apt/lists/*

# The SDK archive is verified against the checksum Google publishes in
# releases_linux.json before anything in it runs.
RUN curl -fsSL -o /tmp/flutter.tar.xz \
      "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz" \
 && echo "${FLUTTER_SHA256}  /tmp/flutter.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/flutter.tar.xz -C /opt \
 && rm /tmp/flutter.tar.xz \
 && git config --global --add safe.directory /opt/flutter

ENV PATH=/opt/flutter/bin:$PATH
RUN flutter config --no-analytics >/dev/null && flutter precache --web

WORKDIR /src/mobile
COPY mobile/pubspec.yaml mobile/pubspec.lock ./
RUN flutter pub get
COPY mobile/ ./

# --no-web-resources-cdn bundles CanvasKit and the Roboto fallback font, so
# opening the app fetches no code from Google and works on networks that block
# gstatic.com. Emoji and non-Latin fallback fonts are still fetched from
# fonts.gstatic.com on first use (see Caddyfile.web).
RUN flutter build web --release --no-web-resources-cdn --no-wasm-dry-run \
 && grep -q "__file_picker_web-file-input" build/web/main.dart.js \
 && grep -q "record.worklet.js" build/web/main.dart.js \
 && test -f build/web/canvaskit/canvaskit.wasm

# --- Stage 2: static server ------------------------------------------------
FROM caddy:2-alpine AS runtime

COPY docker/Caddyfile.web /etc/caddy/Caddyfile
COPY --from=build /src/mobile/build/web /srv
# The in-app verification dashboard reads the last scripts/verify.py report.
COPY reports/verification.json /srv/verification.json

# The stock binary carries cap_net_bind_service for ports below 1024. This
# server listens on 8080, and with every capability dropped and
# no-new-privileges set (see compose) the kernel refuses to exec a binary that
# asks for one, so the capability is removed.
RUN setcap -r /usr/bin/caddy

# Non-root, and nothing to persist: Caddy's state goes to a tmpfs.
ENV XDG_CONFIG_HOME=/tmp/caddy XDG_DATA_HOME=/tmp/caddy
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
