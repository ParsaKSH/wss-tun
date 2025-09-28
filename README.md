# wss-tun
a linux core for tunneling tcp into wss

# how to run:

server:
```bash
apt install nginx
cat > /etc/nginx/nginx.conf << 'NGINX'
user www-data;
worker_processes auto;
worker_rlimit_nofile 2000000;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events { use epoll; worker_connections 131072; multi_accept on; }


http {
    sendfile on;
    tcp_nodelay on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    gzip on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
NGINX

cat > /etc/nginx/sites-enabled/wstun.conf << 'WSTUN'
server {
    listen 80;
    listen [::]:80;
    server_name your.domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your.domain.com;

    ssl_certificate     /etc/letsencrypt/live/your.domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    location /ws {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "Upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout  3600s;
        proxy_send_timeout  3600s;
	proxy_request_buffering off;
	proxy_buffering off;
	proxy_set_header Sec-WebSocket-Protocol $http_sec_websocket_protocol;
	proxy_socket_keepalive on;
    }

    location / { return 200 "ok\n"; add_header Content-Type text/plain; }
}
WSTUN

systemctl enable nginx
nginx -t && systemctl reload nginx
```
```bash
./server -listen "127.0.0.1:8080" -key "a-custom-pass" -path "/ws -dial-timeout 7*time.Second -io-timeout 90*time.Second -ping-every 20*time.Second"
```


client(linux only):
```bash
./client -listen "127.0.0.1:1080" -server "wss://your.domain.com/ws" -key "a-custom-pass" -target-ip "192.168.69.85" -target-port "2096"
```
