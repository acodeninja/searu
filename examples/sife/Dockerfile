FROM node:22-bookworm AS web
WORKDIR /web
COPY web/package.json ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM node:22-bookworm AS api
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping curl \
  && rm -rf /var/lib/apt/lists/*
COPY api/package.json ./
RUN npm install
COPY api/ ./
COPY --from=web /web/dist ./public
EXPOSE 8080
CMD ["node", "src/server.js"]
