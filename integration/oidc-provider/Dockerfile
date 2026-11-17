FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
WORKDIR /fixture
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY provider.mjs provider-lock.json test-provider.mjs ./
RUN node --test test-provider.mjs
USER node
CMD ["node", "provider.mjs"]
