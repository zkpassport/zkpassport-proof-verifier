FROM node:22.23.4-trixie-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Packaged circuits to verify against instead of the public registry, if any (see README)
COPY packaged ./packaged
ENV CIRCUITS_DIR=/app/packaged

EXPOSE 8080

CMD ["node", "dist/server.js"]
