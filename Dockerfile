FROM node:22-alpine
WORKDIR /app
COPY . /app
ENV HOST=0.0.0.0 PORT=3000 PEER_HOST=0.0.0.0 PEER_PORT=4101 DATA_DIR=/app/var
EXPOSE 3000 4101
VOLUME ["/app/var"]
CMD ["node","src/main.mjs"]
