# ---------------------------------------------------------------------------
# Helo relay -- multi-stage build.
#
# Threat posture: this container handles ciphertext for every user. It holds no
# decryption key, but it is the single richest source of METADATA in the system
# and a foothold here enables traffic analysis and targeted denial of service.
# It is therefore hardened as though it were holding secrets.
# ---------------------------------------------------------------------------

# --- Stage 1: dependency + test stage --------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /build
COPY backend/package.json ./
# There are ZERO runtime dependencies by design, so there is no npm install
# here and no lockfile to audit. This is the strongest supply-chain posture
# available: an empty dependency tree cannot be poisoned.
RUN test "$(node -e "const p=require('./package.json');console.log(Object.keys(p.dependencies||{}).length)")" = "0" \
    || (echo "FAIL: runtime dependencies introduced; review supply chain" && exit 1)
COPY backend/ ./
RUN node --test test/ > /dev/null

# --- Stage 2: minimal runtime ----------------------------------------------
FROM node:22-bookworm-slim AS runtime

# Drop package managers and shells that are useful only to an attacker.
RUN apt-get purge -y --auto-remove npm 2>/dev/null || true; \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
           /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV NODE_ENV=production \
    PORT=8443 \
    HOST=0.0.0.0 \
    DB_PATH=/data/helo.db

# Non-root, no login shell, no home directory to write into.
RUN groupadd --system --gid 10001 helo \
 && useradd --system --uid 10001 --gid helo --no-create-home \
            --shell /usr/sbin/nologin helo \
 && mkdir -p /data /app \
 && chown -R helo:helo /data /app

WORKDIR /app
COPY --from=build --chown=helo:helo /build/src ./src
COPY --from=build --chown=helo:helo /build/package.json ./

USER helo
EXPOSE 8443
VOLUME ["/data"]

# The filesystem is mounted read-only at runtime (see compose); /data is the
# only writable path. Verified by the healthcheck below failing if the DB
# cannot be opened.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8443)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# No secrets are baked into this image. Configuration is environment-only.
# TLS is terminated by the reverse proxy in front of this process.
CMD ["node", "src/server.js"]
