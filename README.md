[github-license-url]: /blob/master/LICENSE
[docker-url]: https://hub.docker.com/r/maxxt/nginx-jwt-module/

# Nginx jwt auth module
[![Build Status](https://img.shields.io/github/license/maxx-t/nginx-jwt-module.svg)][github-license-url]
[![Build Status](https://img.shields.io/docker/build/maxxt/nginx-jwt-module.svg)][docker-url]
[![Docker pulls](https://img.shields.io/docker/pulls/maxxt/nginx-jwt-module.svg)][docker-url]

This is an NGINX module to check for a valid JWT.

Inspired by [TeslaGov](https://github.com/TeslaGov/ngx-http-auth-jwt-module) and [ch1bo](https://github.com/ch1bo/nginx-jwt), this module is made to be as light as possible and remain simple.
 - Docker image based on the [official nginx Dockerfile](https://github.com/nginxinc/docker-nginx) (alpine).
 - Light image (uncompressed: ~11MB, compressed: ~6MB).

## Build:
This module is built inside a docker container, from the [alpine](https://hub.docker.com/_/alpine/) image.

## Module:

### Example Configuration:
```nginx
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

    location /not-secure/ {}
}
```
### Directives:

    Syntax:	 auth_jwt $variable | on | off;
    Default: auth_jwt off;
    Context: http, server, location

Enables validation of JWT.

    Syntax:	 auth_jwt_key string [encoding];
    Default: ——
    Context: http, server, location

Specifies the key for validating JWT signature (must be hexadecimal).
The *encoding* otpion may be `hex | utf8 | base64` (default is utf8).

    Syntax:	 auth_jwt_key_file filename;
    Default: ——
    Context: http, server, location

Specifies a public key file for validating JWT signature.

### Build:
```bash
./build # Will create a "jwt-nginx" (Dockerfile)
```

### Test:
#### Default usage:
```bash
./test # Will create a "jwt-nginx-test" image from the "jwt-nginx" one (Dockerfile.test)
```
#### Set image name:
```bash
./test your-image-to-test
```
example:
```bash
./test jwt-nginx-s4 # tests the development image
```
#### Use current container:
```bash
./test --current container
```
example:
```bash
# docker run --rm --name ngx-test -p 8000:8000 jwt-nginx-test
./test --current ngx-test
```
