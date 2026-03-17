FROM node:20-slim

RUN apt-get update && apt-get install -y \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/package.json ./

RUN npm install

COPY app/ ./

COPY config/nginx.conf /etc/nginx/nginx.conf

COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN mkdir -p /var/log/nginx /var/log/supervisor /run

COPY flag.txt /flag.txt

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
