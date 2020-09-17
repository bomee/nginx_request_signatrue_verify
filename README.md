# nginx_request_signatrue_verify
Signature request and verify in nginx

## Usage
``` bash
docker run -itd --name openresty -p 80:80 \
    -v /path/nginx_request_signatrue_verify:/usr/local/openresty/nginx/conf \
    openresty/openresty
```
