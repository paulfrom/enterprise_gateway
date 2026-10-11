# Multi-stage build for enterprise-admin-web
# Build context must be repo root: docker build -f apps/admin-web/Dockerfile -t enterprise-admin-web:<tag> .

FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS builder

WORKDIR /workspace

# Copy root workspace manifests
COPY package.json package-lock.json .node-version ./

# Copy OpenAPI contract
COPY contracts/admin.openapi.json ./contracts/

# Copy admin-web package
COPY apps/admin-web/ ./apps/admin-web/

# Install exact dependencies from root lockfile
RUN npm ci

# Generate types and build production dist
RUN npm run build --workspace apps/admin-web

# Production serving image
FROM nginx:alpine@sha256:df221db836e1754089190208cee7eeda94f233197056426eda74a43ab1abeac2

# Copy built static dist
RUN rm -rf /usr/share/nginx/html/*
COPY --from=builder /workspace/apps/admin-web/dist /usr/share/nginx/html

# Serve the SPA and proxy API requests through the same origin.
COPY deploy/nginx/admin.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
