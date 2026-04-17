FROM node:22-slim AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY --from=zkp packages/zkpassport-sdk  /tmp/zkp/sdk
COPY --from=zkp packages/zkpassport-utils /tmp/zkp/utils
COPY --from=zkp packages/registry-sdk    /tmp/zkp/registry
RUN rm -rf node_modules/@zkpassport/sdk node_modules/@zkpassport/utils node_modules/@zkpassport/registry \
 && cp -r /tmp/zkp/sdk      node_modules/@zkpassport/sdk \
 && cp -r /tmp/zkp/utils     node_modules/@zkpassport/utils \
 && cp -r /tmp/zkp/registry  node_modules/@zkpassport/registry \
 && rm -rf node_modules/@zkpassport/sdk/node_modules \
           node_modules/@zkpassport/utils/node_modules \
           node_modules/@zkpassport/registry/node_modules \
           /tmp/zkp

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY package.json ./
COPY circuits ./circuits

EXPOSE 8080

CMD ["node", "dist/server.js"]
