[github-license-url]: /blob/master/LICENSE
[action-docker-url]: https://github.com/max-lt/nginx-jwt-module/actions/workflows/docker.yml
[github-container-url]: https://github.com/max-lt/nginx-jwt-module/pkgs/container/nginx-jwt-module

# Nginx jwt auth module
[![License](https://img.shields.io/github/license/maxx-t/nginx-jwt-module.svg)][github-license-url]
[![Build Status](https://github.com/max-lt/nginx-jwt-module/actions/workflows/docker.yml/badge.svg)][action-docker-url]
[![Build Status](https://ghcr-badge.deta.dev/max-lt/nginx-jwt-module/size)][action-docker-url]

This is an NGINX module to check for a valid JWT.

Inspired by [TeslaGov](https://github.com/TeslaGov/ngx-http-auth-jwt-module), [ch1bo](https://github.com/ch1bo/nginx-jwt) and [tizpuppi](https://github.com/tizpuppi/ngx_http_auth_jwt_module), this module intend to be as light as possible and to remain simple.
 - Docker image based on the [official nginx Dockerfile](https://github.com/nginxinc/docker-nginx) (alpine).
 - Light image (~16MB).

### Module:

#### Example Configuration:
```nginx
# nginx.conf
load_module /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so;
```

```nginx
# server.conf
server {
    auth_jwt_key "0123456789abcdef" hex; # Your key as hex string
    auth_jwt     off;

    location /secured-by-cookie/ {
        auth_jwt $cookie_MyCookieName;
    }

    location /secured-by-auth-header/ {
        auth_jwt on;
    }

    location /secured-by-auth-header-too/ {
        auth_jwt_key "another-secret"; # Your key as utf8 string
        auth_jwt on;
    }

    location /secured-by-rsa-key/ {
        auth_jwt_key /etc/keys/rsa-public.pem file; # Your key from a PEM file
        auth_jwt on;
    }

    location /not-secure/ {}
}
```

> Note: don't forget to [load](http://nginx.org/en/docs/ngx_core_module.html#load_module) the module in the main context: <br>`load_module /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so;`

### Directives:

    Syntax:	 auth_jwt $variable | on | off;
    Default: auth_jwt off;
    Context: http, server, location

Enables validation of JWT.<hr>

    Syntax:	 auth_jwt_key value [encoding];
    Default: ——
    Context: http, server, location

Specifies the key for validating JWT signature (must be hexadecimal).<br>
The *encoding* otpion may be `hex | utf8 | base64 | file` (default is `utf8`).<br>
The `file` option requires the *value* to be a valid file path (pointing to a PEM encoded key).

<hr>

    Syntax:	 auth_jwt_alg any | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512;
    Default: auth_jwt_alg any;
    Context: http, server, location

Specifies which algorithm the server expects to receive in the JWT.

### Image:
Image is generated with Github Actions (see [nginx-jwt-module:latest][github-container-url])

```
docker pull ghcr.io/max-lt/nginx-jwt-module:latest
```

#### Simply create your image from Github's generated one
```dockerfile
FROM ghcr.io/max-lt/nginx-jwt-module:latest

# Copy you nginx conf
# Don't forget to include this module in your configuration
# load_module /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so;
COPY my-nginx-conf /etc/nginx

EXPOSE 8000

STOPSIGNAL SIGTERM

CMD ["nginx", "-g", "daemon off;"]
```

### Build:
This module is built inside a docker container, from the [nginx](https://hub.docker.com/_/nginx/)-alpine image.

```bash
docker build -f Dockerfile -t jwt-nginx . # Will create a "jwt-nginx" image
```

### Test:

#### Default usage:
```bash
make test # Will build a test image & run test suite
```
