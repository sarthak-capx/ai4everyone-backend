# Stage 1: Build
FROM node:20 AS build

WORKDIR /app

# Install dependencies using lockfile
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Prune dev dependencies so we only ship production modules
RUN npm prune --omit=dev

# Stage 2: Production runtime
FROM node:20-slim AS production

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5000

# Copy only what we need to run
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/dist ./dist

# Copy environment file into image (provide backend/.env before build)
COPY .env ./.env

EXPOSE 5000

CMD ["node", "dist/index.js"]

