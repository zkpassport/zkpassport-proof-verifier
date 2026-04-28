FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
COPY zkpassport-sdk-*.tgz zkpassport-utils-*.tgz ./
COPY circuits ./circuits
RUN npm install

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

EXPOSE 8080

CMD ["node", "dist/server.js"]
