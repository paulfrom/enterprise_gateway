# Multi-stage build for enterprise-admin-web
# Build context must be repo root: docker build -f apps/admin-web/Dockerfile -t enterprise-admin-web:<tag> .

FROM node:22-alpine AS builder

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
FROM nginx:alpine

# Copy built static dist
COPY --from=builder /workspace/apps/admin-web/dist /usr/share/nginx/html

# Deploy Nginx reverse proxy configuration (deploy/nginx/admin.conf) is integrated in deployment stage (M3)
# COPY deploy/nginx/admin.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
