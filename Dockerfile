FROM node:24-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json tsconfig.json .eslintrc.js .prettierrc ./
COPY src ./src
RUN npm ci && npm run build

FROM node:24-alpine
WORKDIR /app
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
ENV NODE_ENV=production
CMD ["node", "dist/server.js"]
