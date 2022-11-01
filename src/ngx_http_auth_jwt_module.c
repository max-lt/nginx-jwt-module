#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <jwt.h>
#include <jansson.h>

typedef struct {
  ngx_str_t jwt_key;            // Forwarded key (with auth_jwt_key)
  ngx_int_t jwt_flag;           // Function of "auth_jwt": on -> 1 | off -> 0 | $variable -> 2
  ngx_int_t jwt_var_index;      // Used only if jwt_flag==2 to fetch the $variable value
  ngx_uint_t jwt_algorithm;     // Member of ngx_http_auth_jwt_algorithms, defaults to JWT_ALG_ANY
  ngx_array_t* jwt_require;     // ngx_int_t array of auth_jwt_require indexes
  ngx_uint_t jwt_require_error; // error code (401|403) to use when jwt_require rejects the request
} ngx_http_auth_jwt_loc_conf_t;

#define NGX_HTTP_AUTH_JWT_OFF        0
#define NGX_HTTP_AUTH_JWT_BEARER     1
#define NGX_HTTP_AUTH_JWT_VARIABLE   2

#define NGX_HTTP_AUTH_JWT_ENCODING_HEX     0
#define NGX_HTTP_AUTH_JWT_ENCODING_BASE64  1
#define NGX_HTTP_AUTH_JWT_ENCODING_UTF8    2

#define JWT_ALG_ANY JWT_ALG_NONE

/*
 * Enum of accepted jwt algorithms, mapped on the libjwt one.
 * Note that the "any" string is mapped on the JWT_ALG_ANY=JWT_ALG_NONE value to avoid conflict with other ones.
 */
static ngx_conf_enum_t ngx_http_auth_jwt_algorithms[] = {
  { ngx_string("HS256"), JWT_ALG_HS256 },
  { ngx_string("HS384"), JWT_ALG_HS384 },
  { ngx_string("HS512"), JWT_ALG_HS512 },
  { ngx_string("RS256"), JWT_ALG_RS256 },
  { ngx_string("RS384"), JWT_ALG_RS384 },
  { ngx_string("RS512"), JWT_ALG_RS512 },
  { ngx_string("ES256"), JWT_ALG_ES256 },
  { ngx_string("ES384"), JWT_ALG_ES384 },
  { ngx_string("ES512"), JWT_ALG_ES512 },
  { ngx_string("any"), JWT_ALG_ANY }
};

static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_jwt_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t auth_jwt_get_token(u_char **token, ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf);
static char * auth_jwt_key_from_file(ngx_conf_t *cf, const char *path, ngx_str_t *key);
static u_char * auth_jwt_safe_string(ngx_pool_t *pool, u_char *src, size_t len);

// Configuration functions
static ngx_int_t ngx_http_auth_jwt_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static void * ngx_http_auth_jwt_create_conf(ngx_conf_t *cf);
static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child);

// Declaration functions
static char * ngx_conf_set_auth_jwt_require(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_conf_set_auth_jwt_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_conf_set_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_auth_jwt_commands[] = {

  // auth_jwt_key value [hex | base64 | utf8 | file];
  { ngx_string("auth_jwt_key"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    ngx_conf_set_auth_jwt_key,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_key),
    NULL },

  // auth_jwt $variable | off | on;
  { ngx_string("auth_jwt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_auth_jwt,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_flag),
    NULL },

  // auth_jwt_alg HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512;
  { ngx_string("auth_jwt_alg"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_enum_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_algorithm),
    &ngx_http_auth_jwt_algorithms },

  // auth_jwt_require $value ... [error=401 | 403] ;
  { ngx_string("auth_jwt_require"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_conf_set_auth_jwt_require,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_require),
    NULL },

  ngx_null_command
};

static ngx_http_variable_t ngx_http_auth_jwt_variables[] = {

  { ngx_string("jwt_headers"),
    NULL,
    ngx_http_auth_jwt_variable,
    1, NGX_HTTP_VAR_NOCACHEABLE, 0 },

  { ngx_string("jwt_payload"),
    NULL,
    ngx_http_auth_jwt_variable,
    2, NGX_HTTP_VAR_NOCACHEABLE, 0 },

  { ngx_string("jwt_header_"),
    NULL,
    ngx_http_auth_jwt_variable,
    0, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX, 0 },

  { ngx_string("jwt_claim_"),
    NULL,
    ngx_http_auth_jwt_variable,
    0, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX, 0 },

  ngx_http_null_variable
};


static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
  ngx_http_auth_jwt_add_variables, /* preconfiguration */
  ngx_http_auth_jwt_init,          /* postconfiguration */

  NULL,                            /* create main configuration */
  NULL,                            /* init main configuration */

  NULL,                            /* create server configuration */
  NULL,                            /* merge server configuration */

  ngx_http_auth_jwt_create_conf,   /* create location configuration */
  ngx_http_auth_jwt_merge_conf     /* merge location configuration */
};


ngx_module_t ngx_http_auth_jwt_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_jwt_module_ctx,     /* module context */
  ngx_http_auth_jwt_commands,        /* module directives */
  NGX_HTTP_MODULE,                   /* module type */
  NULL,                              /* init master */
  NULL,                              /* init module */
  NULL,                              /* init process */
  NULL,                              /* init thread */
  NULL,                              /* exit thread */
  NULL,                              /* exit process */
  NULL,                              /* exit master */
  NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
  const ngx_http_auth_jwt_loc_conf_t *conf;
  u_char *jwt_data;
  jwt_t *jwt = NULL;

  conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

  // Pass through if "auth_jwt" is "off"
  if (conf->jwt_flag == NGX_HTTP_AUTH_JWT_OFF)
  {
    return NGX_DECLINED;
  }

  // Pass through options requests without token authentication
  if (r->method == NGX_HTTP_OPTIONS)
  {
    return NGX_DECLINED;
  }

  // Get jwt
  if (auth_jwt_get_token(&jwt_data, r, conf) != NGX_OK)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to find a jwt");
    return NGX_HTTP_UNAUTHORIZED;
  }

  // Validate the jwt
  if (jwt_decode(&jwt, (char *)jwt_data, conf->jwt_key.data, conf->jwt_key.len))
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to parse jwt");
    return NGX_HTTP_UNAUTHORIZED;
  }
  // jwt_decode succeeded and allocated an jwt object.
  // We register jwt_free as a function to be called on pool cleanup.
  ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
  if (cln == NULL)
  {
    jwt_free(jwt);
    return NGX_ERROR;
  }
  cln->handler = (ngx_pool_cleanup_pt)jwt_free;
  cln->data = jwt;

  // Set jwt as module context
  ngx_http_set_ctx(r, jwt, ngx_http_auth_jwt_module);

  // Validate the algorithm
  jwt_alg_t alg = jwt_get_alg(jwt);
  // Reject incoming token with a "none" algorithm, or, if auth_jwt_alg is set, those with a different one.
  if (alg == JWT_ALG_NONE || (conf->jwt_algorithm != JWT_ALG_ANY && conf->jwt_algorithm != alg))
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: invalid algorithm in jwt %s", jwt_alg_str(jwt_get_alg(jwt)));
    return NGX_HTTP_UNAUTHORIZED;
  }

  // Validate the exp date of the JWT; Still valid if "exp" missing (exp == -1)
  time_t exp = (time_t)jwt_get_grant_int(jwt, "exp");
  if (exp != -1 && exp < time(NULL))
  {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT: the jwt has expired [exp=%ld]", (long)exp);
    return NGX_HTTP_UNAUTHORIZED;
  }

  // Validate jwt_require
  if (conf->jwt_require != NGX_CONF_UNSET_PTR)
  {
    ngx_uint_t i;
    for (i = 0; i < conf->jwt_require->nelts; i++) {
      const ngx_int_t var_index = ((ngx_int_t *) conf->jwt_require->elts)[i];
      const ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, var_index);
      if (value == NULL || value->not_found || value->len == 0) {
        return conf->jwt_require_error;
      }

      // Value found but is "0"
      if (value->len == 1 && value->data[0] == '0') {
        return conf->jwt_require_error;
      }
    }
  }

  return NGX_OK;
}


static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL)
  {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_jwt_handler;

  return NGX_OK;
}


static void * ngx_http_auth_jwt_create_conf(ngx_conf_t *cf)
{
  ngx_http_auth_jwt_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
  if (conf == NULL)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: conf==NULL");
    return NULL;
  }

  // Initialize variables
  ngx_str_null(&conf->jwt_key);
  conf->jwt_flag = NGX_CONF_UNSET;
  conf->jwt_var_index = NGX_CONF_UNSET;
  conf->jwt_algorithm = NGX_CONF_UNSET_UINT;
  conf->jwt_require = NGX_CONF_UNSET_PTR;
  conf->jwt_require_error = NGX_CONF_UNSET_UINT;

  return conf;
}


static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_jwt_loc_conf_t *prev = parent;
  ngx_http_auth_jwt_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->jwt_key, prev->jwt_key, NULL);
  ngx_conf_merge_value(conf->jwt_var_index, prev->jwt_var_index, NGX_CONF_UNSET);
  ngx_conf_merge_value(conf->jwt_flag, prev->jwt_flag, NGX_HTTP_AUTH_JWT_OFF);
  ngx_conf_merge_uint_value(conf->jwt_algorithm, prev->jwt_algorithm, JWT_ALG_ANY);
  ngx_conf_merge_uint_value(conf->jwt_require_error, prev->jwt_require_error, 401);
  ngx_conf_merge_ptr_value(conf->jwt_require, prev->jwt_require, NGX_CONF_UNSET_PTR);

  // If auth_jwt is active, we must have a key
  if (conf->jwt_flag != NGX_HTTP_AUTH_JWT_OFF && conf->jwt_key.data == NULL) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: key not set");
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}


// Convert an hexadecimal string to a binary string
static int hex_to_binary(u_char* dest, u_char* src, const size_t n)
{
  u_char *p = &dest[0];
  ngx_int_t dst;
  size_t i;
  for (i = 0; i < n; i += 2) {
    dst = ngx_hextoi(&src[i], 2);

    if (dst == NGX_ERROR || dst > 255)
    {
      return NGX_ERROR;
    }

    *p++ = (u_char) dst;
  }

  return NGX_OK;
}


// Assign key from file
static char * auth_jwt_key_from_file(ngx_conf_t *cf, const char *path, ngx_str_t *key)
{
  // Determine file size (avoiding fseek)
  struct stat fstat;
  if (stat(path, &fstat) < 0)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, errno, strerror(errno));
    return NGX_CONF_ERROR;
  }

  FILE *fp = fopen(path, "rb");
  if (fp == NULL)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, errno, strerror(errno));
    return NGX_CONF_ERROR;
  }

  key->len = fstat.st_size;
  key->data = ngx_pcalloc(cf->pool, key->len);

  if (fread(key->data, 1, key->len, fp) != key->len)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "jwt_key file: unexpected end of file");
    fclose(fp);
    return NGX_CONF_ERROR;
  }

  fclose(fp);

  return NGX_CONF_OK;
}


// Parse auth_jwt_require directive
static char * ngx_conf_set_auth_jwt_require(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t *ajcf = conf;
  ngx_array_t **a = &ajcf->jwt_require;
  ngx_str_t *elts = cf->args->elts;

  if (*a != NGX_CONF_UNSET_PTR) {
    return "is duplicate";
  }

  *a = ngx_array_create(cf->pool, 4, sizeof(ngx_int_t));
  if (*a == NULL) {
    return NGX_CONF_ERROR;
  }

  ngx_uint_t i;
  for (i = 1; i < cf->args->nelts; i++) {
    ngx_str_t var = elts[i];

    if (ngx_strncmp(var.data, "error=", 6) == 0) {
      if (i != cf->args->nelts -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s must be the last element of jwt_auth_require directive", var.data);
        return NGX_CONF_ERROR;
      }

      if (i == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s cannot be the single element of jwt_auth_require directive", var.data);
        return NGX_CONF_ERROR;
      }

      // Parse code to int
      ngx_int_t code = ngx_atoi(var.data + 6, var.len - 6);
      if (code < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to parse error code %s", var.data + 6);
        return NGX_CONF_ERROR;
      }

      // Error code must be 401 or 403
      if (code != 401 && code != 403) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid error code %d", code);
        return NGX_CONF_ERROR;
      }

      ajcf->jwt_require_error = code;

      continue;
    }

    if (var.data[0] != '$') {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &var);
      return NGX_CONF_ERROR;
    }

    // Get variable index
    ngx_str_t str = { .data = var.data + 1, .len = var.len - 1 };
    ngx_int_t index = ngx_http_get_variable_index(cf, &str);
    if (index == NGX_ERROR)
    {
      ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Cannot get index for variable %s", var.data);
      return NGX_CONF_ERROR;
    }

    // Push variable index to require
    ngx_int_t *elt = ngx_array_push(*a);
    if (elt == NULL) {
      return NGX_CONF_ERROR;
    }

    *elt = index;
  }

  return NGX_CONF_OK;
}


// Parse auth_jwt_key directive
static char * ngx_conf_set_auth_jwt_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t *ajcf = conf;
  ngx_str_t *key = &ajcf->jwt_key;
  ngx_str_t *value = (ngx_str_t *) cf->args->elts;
  ngx_uint_t encoding;

  // If jwt_key.data not null
  if (key->data != NULL)
  {
    return "is duplicate";
  }

  // If there is only the key string;
  if (cf->args->nelts == 2)
  {
    encoding = NGX_HTTP_AUTH_JWT_ENCODING_UTF8;
  }
  // We can have (auth_jwt_key value [encoding | file])
  else if (cf->args->nelts == 3)
  {
    if (ngx_strcmp(value[2].data, "file") == 0)
    {
      const char *path = (char *)auth_jwt_safe_string(cf->pool, value[1].data, value[1].len);
      return auth_jwt_key_from_file(cf, path, key);
    }
    else if (ngx_strcmp(value[2].data, "hex") == 0)
    {
      encoding = NGX_HTTP_AUTH_JWT_ENCODING_HEX;
    }
    else if (ngx_strcmp(value[2].data, "base64") == 0)
    {
      encoding = NGX_HTTP_AUTH_JWT_ENCODING_BASE64;
    }
    else if (ngx_strcmp(value[2].data, "utf8") == 0)
    {
      encoding = NGX_HTTP_AUTH_JWT_ENCODING_UTF8;
    }
    else
    {
      return NGX_CONF_ERROR;
    }
  }
  else
  {
    return NGX_CONF_ERROR;
  }

  ngx_str_t *keystr = &value[1];

  if (keystr->len == 0 || keystr->data == NULL)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid key");
    return NGX_CONF_ERROR;
  }

  switch (encoding)
  {
    case NGX_HTTP_AUTH_JWT_ENCODING_HEX:
    {
      // Parse provided key
      if (keystr->len % 2)
      {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid hex string");
        return NGX_CONF_ERROR;
      }

      key->data = ngx_palloc(cf->pool, keystr->len / 2);
      key->len = keystr->len / 2;

      if (hex_to_binary(key->data, keystr->data, keystr->len) != NGX_OK)
      {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Failed to turn hex key into binary");
        return NGX_CONF_ERROR;
      }

      return NGX_CONF_OK;
    }
    case NGX_HTTP_AUTH_JWT_ENCODING_BASE64:
    {
      key->len = ngx_base64_decoded_length(keystr->len);
      key->data = ngx_palloc(cf->pool, key->len);

      if (ngx_decode_base64(key, keystr) != NGX_OK)
      {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Failed to turn base64 key into binary");
        return NGX_CONF_ERROR;
      }

      return NGX_CONF_OK;
    }
    case NGX_HTTP_AUTH_JWT_ENCODING_UTF8:
    {
      key->data = keystr->data;
      key->len = keystr->len;

      return NGX_CONF_OK;
    }
  }

  return NGX_CONF_ERROR;
}


// Parse auth_jwt directive
static char * ngx_conf_set_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t *ajcf = conf;
  ngx_int_t *flag = &ajcf->jwt_flag;

  if (*flag != NGX_CONF_UNSET)
  {
    return "is duplicate";
  }

  const ngx_str_t *value = cf->args->elts;

  const ngx_str_t var = value[1]; // on | off | $variable

  if (var.len == 0)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid value");
    return NGX_CONF_ERROR;
  }

  // Check if enabled, if not: return conf.
  if (var.len == 3 && ngx_strncmp(var.data, "off", 3) == 0)
  {
    *flag = NGX_HTTP_AUTH_JWT_OFF;
  }
  // If enabled and "on" we will get token from "Authorization" header.
  else if (var.len == 2 && ngx_strncmp(var.data, "on", 2) == 0)
  {
    *flag = NGX_HTTP_AUTH_JWT_BEARER;
  }
  // Else we will get token from passed variable.
  else
  {
    *flag = NGX_HTTP_AUTH_JWT_VARIABLE;

    if (var.data[0] != '$')
    {
      ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid variable name %s", var.data);
      return NGX_CONF_ERROR;
    }

    ngx_str_t str = { .data = var.data + 1, .len = var.len - 1 };
    ajcf->jwt_var_index = ngx_http_get_variable_index(cf, &str);
    if (ajcf->jwt_var_index == NGX_ERROR)
    {
      ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Cannot get index for variable %s", var.data);
      return NGX_CONF_ERROR;
    }
  }

  return NGX_CONF_OK;
}


// Copy a character array into a null terminated one.
static u_char * auth_jwt_safe_string(ngx_pool_t *pool, u_char *src, size_t len)
{
  u_char  *dst;

  dst = ngx_pcalloc(pool, len + 1);
  if (dst == NULL)
  {
    return NULL;
  }

  ngx_memcpy(dst, src, len);

  dst[len] = '\0';

  return dst;
}


static ngx_int_t auth_jwt_get_token(u_char **token, ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf)
{
  static const ngx_str_t bearer = ngx_string("Bearer ");
  const ngx_int_t flag = conf->jwt_flag;

  if (flag == NGX_HTTP_AUTH_JWT_BEARER)
  {
    if (r->headers_in.authorization == NULL)
    {
      return NGX_DECLINED;
    }

    ngx_str_t header = r->headers_in.authorization->value;

    // If the "Authorization" header value is less than "Bearer X" length, there is no reason to continue.
    if (header.len < bearer.len + 1)
    {
     ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Invalid Authorization length");
     return NGX_DECLINED;
    }
    // If the "Authorization" header does not starts with "Bearer ", return NULL.
    if (ngx_strncmp(header.data, bearer.data, bearer.len) != 0)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Invalid authorization header content");
      return NGX_DECLINED;
    }

    *token = auth_jwt_safe_string(r->pool, header.data + bearer.len, (size_t) header.len - bearer.len);
  }
  else if (flag == NGX_HTTP_AUTH_JWT_VARIABLE)
  {
    ngx_http_variable_value_t * value = ngx_http_get_indexed_variable(r, conf->jwt_var_index);

    if (value == NULL || value->not_found || value->len == 0)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Variable not found or empty.");
      return NGX_DECLINED;
    }

    *token = auth_jwt_safe_string(r->pool, value->data, value->len);
  }
  else
  {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: Invalid flag [%d]", flag);
    return NGX_ERROR;
  }

  if (token == NULL)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "Could not allocate memory.");
    return NGX_ERROR;
  }

  return NGX_OK;
}


static ngx_int_t ngx_http_auth_jwt_add_variables(ngx_conf_t *cf) {
  ngx_http_variable_t *jv, *v;

  for (jv = ngx_http_auth_jwt_variables; jv->name.len; jv++) {
    v = ngx_http_add_variable(cf, &jv->name, jv->flags);
    if (v == NULL) {
      return NGX_ERROR;
    }

    *v = *jv;
  }

  return NGX_OK;
}


static ngx_int_t ngx_http_auth_jwt_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
  v->not_found = 1;

  // Get jwt from module context
  jwt_t *jwt = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
  if (!jwt) {
    return NGX_OK;
  }

  const char *value = NULL;

  switch (data)
  {
    case 1:
      value = jwt_get_headers_json(jwt, NULL);
      break;

    case 2:
      value = jwt_get_grants_json(jwt, NULL);
      break;

    // Data is overwritten with NGX_HTTP_VAR_PREFIX
    // so its either jwt_header_ or jwt_claim_
    default:
    {
      const ngx_str_t *name = (ngx_str_t *) data;

      // Are we looking for claim (0) or header (1)
      const ngx_uint_t h = name->data[4] == 'h';

      // Prefix length
      const ngx_uint_t plen = h ? (sizeof("jwt_header_") - 1) : (sizeof("jwt_claim_") - 1);

      // Value without prefix and null terminated
      const char *val = (char *)auth_jwt_safe_string(r->pool, name->data + plen, name->len - plen);

      value = h ? jwt_get_headers_json(jwt, val) : jwt_get_grants_json(jwt, val);
    }
  }

  if (value == NULL) {
    return NGX_OK;
  }

  v->data = (u_char *) value;
  v->len = ngx_strlen(value);
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  return NGX_OK;
}
