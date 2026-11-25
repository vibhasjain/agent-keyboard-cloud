FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src src
COPY public public
ENV DATA_DIR=/data PORT=8080 NODE_ENV=production
CMD ["node", "src/server.mjs"]
