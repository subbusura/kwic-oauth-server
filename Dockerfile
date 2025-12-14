FROM node:22-alpine3.20 AS builder
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json .eslintrc.js .prettierrc ./
COPY src ./src
RUN npm install --production=false
RUN npm run build

FROM node:22-alpine3.20
WORKDIR /app
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --chown=nodejs:nodejs public ./dist/public
COPY --chown=nodejs:nodejs views ./dist/views
USER nodejs
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/src/server.js"]
