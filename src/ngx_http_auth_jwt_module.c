#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

#include <jansson.h>

typedef struct {
	ngx_str_t   jwt_key;          // Forwarded: key as hexadecimal string
	ngx_str_t   jwt_var;          // Forwarded: as "auth_jwt" value: on | off | $variable
	ngx_str_t   jwt_bin_key;      // Computed: "jwt_key" in binary.
	ngx_flag_t  jwt_flag;         // Computed: function of jwt_var: on -> 1 | off -> 0 | $variable -> 2
	ngx_int_t   jwt_var_index;    // Computed: useful only if jwt_flag==2 ->
} ngx_http_auth_jwt_loc_conf_t;

#define NGX_HTTP_AUTH_JWT_OFF     0
#define NGX_HTTP_AUTH_JWT_DEFAULT 1
#define NGX_HTTP_AUTH_JWT_VALUE   2

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static void * ngx_http_auth_jwt_create_conf(ngx_conf_t *cf);
static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t auth_jwt_get_token(char **token, ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf);

static ngx_command_t ngx_http_auth_jwt_commands[] = {

  // todo: auth_jwt_key "key" [encoding = ascii | hex | base64]
  // auth_jwt_key "hexadecimal key";
	{ ngx_string("auth_jwt_key"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_key),
		NULL },

  // todo: auth_jwt_key_file "file location"

  // auth_jwt $variable | off | on;
	{ ngx_string("auth_jwt"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_var),
		NULL },

	ngx_null_command
};


static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
	NULL,                        /* preconfiguration */
	ngx_http_auth_jwt_init,      /* postconfiguration */

	NULL,                        /* create main configuration */
	NULL,                        /* init main configuration */

	NULL,                        /* create server configuration */
	NULL,                        /* merge server configuration */

	ngx_http_auth_jwt_create_conf,             /* create location configuration */
	ngx_http_auth_jwt_merge_conf               /* merge location configuration */
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
	const ngx_http_auth_jwt_loc_conf_t * conf;
	char* jwt_data;
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

  if (auth_jwt_get_token(&jwt_data, r, conf) != NGX_OK)
	{
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to find a jwt");
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Validate the jwt
	if (jwt_decode(&jwt, jwt_data, conf->jwt_bin_key.data, conf->jwt_bin_key.len))
	{
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to parse jwt");
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Validate the algorithm
	if (jwt_get_alg(jwt) == JWT_ALG_NONE)
	{
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: invalid algorithm in jwt %d", jwt_get_alg(jwt));
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Validate the exp date of the JWT
	time_t exp = (time_t) jwt_get_grant_int(jwt, "exp");
	time_t now = time(NULL);
	if (exp < now)
	{
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT: the jwt has expired");
		return NGX_HTTP_UNAUTHORIZED;
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

	// set the flag to unset
	conf->jwt_flag = (ngx_flag_t) -1;

	ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "JWT: Created Location Configuration %d", conf->jwt_flag);

	return conf;
}


static inline int hex_to_binary(u_char* src, u_char* dest, const size_t n) {
    u_char *p = &dest[0];
    ngx_int_t dst;
    for (size_t i = 0; i < n; i += 2) {
      dst = ngx_hextoi(&src[i], 2);
      if (dst == NGX_ERROR || dst > 255) {
        return NGX_ERROR;
      }
      *p++ = (u_char) dst;
    }
    return NGX_OK;
}


static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_jwt_loc_conf_t *prev = parent;
	ngx_http_auth_jwt_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->jwt_key, prev->jwt_key, "");
	ngx_conf_merge_str_value(conf->jwt_var, prev->jwt_var, "");

	const ngx_str_t key = conf->jwt_key;
	const ngx_str_t var = conf->jwt_var;

	// ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "JWT: merged conf data=%s, key=%s", var.data, key.data);

  // Check if enabled, if not: return conf.
  if (var.len == 3 && ngx_strncmp(var.data, "off", 3) == 0)
  {
    conf->jwt_flag = NGX_HTTP_AUTH_JWT_OFF;
    return NGX_CONF_OK;
  }
  // If enabled and "on" we will get token from "Authorization" header.
  else if (var.len == 2 && ngx_strncmp(var.data, "on", 2) == 0)
  {
    conf->jwt_flag = NGX_HTTP_AUTH_JWT_DEFAULT;
  }
  // Else we will get token from passed variable.
  else
  {
    conf->jwt_flag = NGX_HTTP_AUTH_JWT_VALUE;
	  const ngx_str_t value = conf->jwt_var;

    if(value.len == 0)
    {
	    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid variable length %d", value.len);
	    return NGX_CONF_ERROR;
    }

	  if(value.data[0] != '$')
	  {
	    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid variable name %s", value.data);
	    return NGX_CONF_ERROR;
	  }

    ngx_str_t str = { .data = value.data + 1, .len = value.len - 1 };

    ngx_int_t n = ngx_http_get_variable_index(cf, &str);
    if (n == NGX_ERROR) {
	    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Can get index for {data: %s, len: %d}", value.data, value.len);
      return NGX_CONF_ERROR;
    }

	  ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "JWT: Got variable \"%s\", at index [%d]", value.data, n);
	  conf->jwt_var_index = n;

  }

  // Parse provided key
  if (key.len % 2)
	{
	  // todo: check alphabet
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid hex string");
	  return NGX_CONF_ERROR;
	}

  conf->jwt_bin_key.data = ngx_palloc(cf->pool, key.len / 2);
  conf->jwt_bin_key.len = key.len / 2;
  if (0 != hex_to_binary(key.data, conf->jwt_bin_key.data, key.len))
	{
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Failed to turn hex key into binary");
		return NGX_CONF_ERROR;
	}

  // todo : NGX_CONF_ERROR
	return NGX_CONF_OK;
}


static ngx_int_t auth_jwt_get_token(char ** token, ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf)
{
  static const ngx_str_t bearer = ngx_string("Bearer ");
	const ngx_flag_t flag = conf->jwt_flag;

	if(flag == NGX_HTTP_AUTH_JWT_DEFAULT)
  {
    if(r->headers_in.authorization == NULL)
    {
      return NGX_DECLINED;
    }

    ngx_str_t header = r->headers_in.authorization->value;
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: Found authorization header [%s] len=%d", header.data, header.len);

	  if(header.len < bearer.len)
	  {
	   ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Invalid Authorization length");
	   return NGX_DECLINED;
	  }

    // If tha "Authorization" header does not starts with "Bearer ", return NULL.
		if (ngx_strncmp(header.data, bearer.data, bearer.len) != 0)
    {
	    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Invalid authorization header content");
	    return NGX_DECLINED;
    }

    *token = (char *) header.data + bearer.len;
	  return NGX_OK;
  }
	else if (flag == NGX_HTTP_AUTH_JWT_VALUE)
  {
    ngx_http_variable_value_t * value = ngx_http_get_indexed_variable(r, conf->jwt_var_index);

    if(value == NULL || value->not_found || value->len == 0)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Variable not found or empty.");
      return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Variable found: %s={ len: %d, valid: %d, no_cacheable: %d, not_found: %d, data: %s }",
    conf->jwt_var.data, value->len, value->valid, value->no_cacheable, value->not_found, value->data);

    *token = (char *) value->data;
	  return NGX_OK;
  }
	else
	{
	  ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: Invalid flag [%d]", flag);
	  return NGX_ERROR;
	}

	return NGX_ERROR;
}
