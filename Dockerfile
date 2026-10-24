# Container image for an INSPECTION-ONLY UnboxAnyRepo web server (for container
# hosts). It contains no Docker CLI, no socket and no sandbox: execution stays
# disabled. Pin the base image by digest for production builds.
FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    UNBOX_RUNNER=disabled
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src ./src
COPY public ./public
COPY rules ./rules
COPY fixtures ./fixtures

USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "src/server.ts"]
