/*
 * Copyright (C) 2012 Luca Sepe
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include <my_global.h>
#include <mysql.h>


#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


#include "ngx_apikey_access_filter_module.h"



/*
 * Callback for installing this filter (post-configuration step)
 */
static 
ngx_int_t ngx_apikey_access_filter_install(ngx_conf_t *cf);

/*
 * Create local configuration callback (init local configuration data)
 */
static void *
ngx_apikey_access_filter_create_loc_conf( ngx_conf_t *cf );

/*
 * Merge local configuration callback (merge/setup local configuration data)
 */
static char *
ngx_apikey_access_filter_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child );

/*
 * Custom parser for the database connection string (local configurarion).
 */
static char *
ngx_apikey_set_dburl (ngx_conf_t * cf, ngx_command_t * cmd, void *conf);


/**
 * Brute force search for one header with the specified name.
 * Thanks to: http://kung-fu-tzu.ru/pages/nginx-headers-management.html
 */
static ngx_table_elt_t *
ngx_apikey_find_request_header(ngx_http_request_t *r, u_char *name, size_t len);

/**
 * Create the HMAC-SHA1 message digest.
 */
static ngx_int_t
ngx_apikey_hamac_sha1_digest( ngx_pool_t *pool, ngx_str_t *key, ngx_str_t *message, ngx_str_t *digest );

/**
 *	Verify the request token digest.
 */
static ngx_int_t
ngx_apikey_verify( ngx_http_request_t *r, ngx_str_t *client_id, ngx_str_t *expire_time, ngx_str_t *client_digest );

/*
 * Query the MySQL dtabase looking for 'client secret' of a specified client id.
 */
static ngx_int_t
ngx_apikey_mysql_fetch_client_secret( ngx_http_request_t *r, MYSQL *con, ngx_str_t *client_id, ngx_str_t *client_secret );

/*
 * Create the expire_time string as unix epoch adding the specified minutes.
 */
static ngx_int_t
ngx_apikey_token_expire_time( ngx_pool_t *pool, size_t minutes_to_add, ngx_str_t *expire_time );


/* Module's directives  */
static ngx_command_t  
ngx_apikey_access_filter_commands[] = {

	/*
     * Enables or Disables the ApiKey access filter.
     *
     *	 apikey_access_filter on;
     */
	{	ngx_string("apikey_access_filter"),					
	  	NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_FLAG,	
  		ngx_conf_set_flag_slot,								
  		NGX_HTTP_LOC_CONF_OFFSET,							
  		offsetof(ngx_apikey_access_filter_loc_conf_t, enable),	
  		NULL },

	/*
     * Connection string for MySQL database (client_id/client_secret provider).
     *
     *	apikey_access_filter_dburl "mysql://apikeyadmin:apikeyadmin@127.0.0.1:3306/APIKEYS";
     */
	{	ngx_string("apikey_access_filter_dburl"),
  		NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
  	 	ngx_apikey_set_dburl,
  	 	NGX_HTTP_LOC_CONF_OFFSET,
  	  	0,
  	  	NULL },

	/*
	 * Expire time (in seconds) for the ApiKey request token.
     *
	 *	apikey_access_filter_expire_time 300;
	 */
	{	ngx_string("apikey_access_filter_expire_time"),
		NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
      	offsetof(ngx_apikey_access_filter_loc_conf_t, expire_time),
      	NULL },

		ngx_null_command
};


/* The Module Context */
static ngx_http_module_t  
ngx_apikey_access_filter_module_ctx = {
    NULL,											/* preconfiguration */
    ngx_apikey_access_filter_install,				/* postconfiguration */

    NULL,											/* create main configuration */
    NULL,											/* init main configuration */

    NULL,											/* create server configuration */
    NULL,											/* merge server configuration */

    ngx_apikey_access_filter_create_loc_conf,		/* create location configuration */
    ngx_apikey_access_filter_merge_loc_conf			/* merge location configuration */
};


/* Module Definition */
ngx_module_t  ngx_apikey_access_filter_module = {
    NGX_MODULE_V1,
    &ngx_apikey_access_filter_module_ctx, 	   	/* module context */
    ngx_apikey_access_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       		/* module type */
    NULL,                                 	 	/* init master */
    NULL,                                  		/* init module */
    NULL,                                  		/* init process */
    NULL,                                  		/* init thread */
    NULL,                                  		/* exit thread */
    NULL,                                  		/* exit process */
    NULL,                                  		/* exit master */
    NGX_MODULE_V1_PADDING
};



static ngx_int_t
ngx_apikey_access_filter_handler( ngx_http_request_t *r ) {

	ngx_apikey_access_filter_loc_conf_t  *lcf = NULL;
	
	ngx_int_t	rc;

	u_char		*last = NULL;

	ngx_str_t 	auth_header_key		= ngx_string("X-AuthAPI");
	ngx_str_t 	auth_header_value	= ngx_null_string;
	
	ngx_str_t 	client_id			= ngx_null_string;
	ngx_str_t	issued_time			= ngx_null_string;
	ngx_str_t	client_digest		= ngx_null_string;
	
	
	/* If the module isn't enabled..let's the request go! */	
    lcf = ngx_http_get_module_loc_conf(r, ngx_apikey_access_filter_module);
    if ( !lcf->enable ) {
		return NGX_OK;
    }
	// ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uri = %V", &r->uri );

	/* Let's look for the request token in the cookies */
	rc = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &auth_header_key, &auth_header_value);
	if ( rc != NGX_DECLINED ) {
		ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"found auth token in cookie with value ( %s )", auth_header_value.data );
	} else {
	/* Nothing in the cookies ? let's search the request headers */
		ngx_table_elt_t	*token_header = ngx_apikey_find_request_header( r, auth_header_key.data, auth_header_key.len );
		if ( token_header ) {
			u_char *last = NULL;
			auth_header_value.len = ngx_strlen( token_header->value.data );
			auth_header_value.data = ngx_pcalloc( r->pool, auth_header_value.len + 1 );
			last = ngx_copy( auth_header_value.data, token_header->value.data, auth_header_value.len );
			*last = (u_char)'\0';
			
			//ngx_str_set( &auth_token_value, token_header->value.data );
			ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
				"found auth token in header with value ( %s ) - (%d)", auth_header_value.data, auth_header_value.len );
		}
	}
	
	/* Nothing found? Access Denied! */
	if ( auth_header_value.data == NULL ) {
		ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "auth token not found neither in request header or cookie" );
		return NGX_HTTP_FORBIDDEN;
	}

	/* Let's parse plain token */
	last =  (u_char *)ngx_strchr( auth_header_value.data, '|' );
	if ( last == NULL ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) while parsing auth token", __func__ );
        return NGX_HTTP_FORBIDDEN;
	}
	
	/* Token parsing: client_id */
	client_id.len = (last - auth_header_value.data);
	client_id.data = ngx_pcalloc( r->pool, client_id.len + 1 );
	if ( client_id.data == NULL ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) failed allocating memory", __func__ );
		return NGX_ERROR;
	}
	last = (u_char *)ngx_copy( client_id.data, auth_header_value.data, client_id.len );
	*last = (u_char)'\0';
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "client id: %s - (%d)", client_id.data, client_id.len );

	/* Token parsing: client_issued_time */
	last = (u_char *)ngx_strchr( auth_header_value.data + (client_id.len + 1), (u_char)'|' );
	if ( last == NULL ) {
		ngx_pfree( r->pool, client_id.data );
		ngx_pfree( r->pool, auth_header_value.data );
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) while parsing auth token", __func__ );
        return NGX_HTTP_FORBIDDEN;
	}

	issued_time.len = ( last - auth_header_value.data - (client_id.len + 1) );
	issued_time.data = ngx_pcalloc( r->pool, issued_time.len + 1 );
	if ( issued_time.data == NULL ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) failed allocating memory", __func__ );
		return NGX_ERROR;
	}
	last = ngx_copy( issued_time.data, auth_header_value.data + client_id.len + 1, issued_time.len  );
	*last = (u_char)'\0';
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request time: %V", &issued_time );

	/* Token parsing: digest */
	client_digest.len = (auth_header_value.len - (client_id.len + 1) - (issued_time.len + 1) );
	if ( client_digest.len <= 1 ) {
		ngx_pfree( r->pool, client_id.data );
		ngx_pfree( r->pool, auth_header_value.data );
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) while parsing auth token", __func__ );
        return NGX_HTTP_FORBIDDEN;
	}

	client_digest.data = ngx_pcalloc( r->pool, client_digest.len + 1 );
	if ( client_digest.data == NULL ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) failed allocating memory", __func__ );
		return NGX_ERROR;
	}
	last = ngx_copy( client_digest.data, auth_header_value.data + (client_id.len + 1) + (issued_time.len + 1), client_digest.len  );
	*last = (u_char)'\0';
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "client digest: %V", &client_digest );

	/* Verify the token digest */
	rc = ngx_apikey_verify( r, &client_id, &issued_time, &client_digest );

	return (rc != NGX_OK) ? NGX_HTTP_FORBIDDEN : NGX_OK;
}


/*
 * Install this filter (post-configuration callback).
 *
 * Filters are installed in the post-configuration step
 */
static ngx_int_t
ngx_apikey_access_filter_install(ngx_conf_t *cf) {

	ngx_http_handler_pt        *h = NULL;
    ngx_http_core_main_conf_t  *cmcf = NULL;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_apikey_access_filter_handler;

    return NGX_OK;
}


/*
 * Create location configuration callback.
 */
static void *
ngx_apikey_access_filter_create_loc_conf(ngx_conf_t *cf) {

    ngx_apikey_access_filter_loc_conf_t *conf = ngx_pcalloc(
		cf->pool, sizeof(ngx_apikey_access_filter_loc_conf_t)
	);

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable 		= NGX_CONF_UNSET;
	conf->expire_time 	= NGX_CONF_UNSET_UINT;

	conf->dbuser		= NULL;
	conf->dbpass		= NULL;
	conf->dbhost		= NULL;
	conf->dbschema		= NULL;
	conf->dbport		= 3306;

    return conf;
}

/*
 * Merge location configuration callback.
 */
static char *
ngx_apikey_access_filter_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child ) {

	ngx_apikey_access_filter_loc_conf_t *prev = parent;
    ngx_apikey_access_filter_loc_conf_t *conf = child;

    ngx_conf_merge_value( conf->enable, prev->enable, 0 );
	ngx_conf_merge_uint_value( conf->expire_time, prev->expire_time	, 10 );

	return NGX_CONF_OK;
}

/*
 * Custom parser for the database connection string (local configurarion).
 */
static char *
ngx_apikey_set_dburl (ngx_conf_t * cf, ngx_command_t * cmd, void *conf) {
	
	ngx_apikey_access_filter_loc_conf_t *lcf = conf;

	size_t 	 len = 0;
	char 	*token		= NULL;

	u_char	*last		= NULL;

	size_t	 cs_len;
	u_char 	*cs			= NULL;


	ngx_str_t *value = cf->args->elts;

	/* check if is a valid URI */
  	token = strstr ( (char *)value[1].data, "mysql://" );
	if ( !token ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "connection string must begin with \'mysql://\'" );
		return NGX_CONF_ERROR;
	}
	
	/* let's skip the URI schema name */
	len = strlen( "mysql://" );
	cs_len = ngx_strlen(value[1].data) - len;
	cs = (u_char *)token + len;

	/* look for database name */
	token = strstr ( (const char *)cs, "/" );
	if ( !token ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "connection string must contain database name" );
		return NGX_CONF_ERROR;
	}
	
	len = strlen(token);
	lcf->dbschema = ngx_pcalloc( cf->pool, len + 1 );
	if ( !lcf->dbschema ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "allocating memory" );
		return NGX_CONF_ERROR;
	}
	last = ngx_copy( lcf->dbschema, (u_char *)(token + 1), len );
	*last = (u_char)'\0';
	token = NULL;

	/* look for login username */
	token = strstr( (const char *)cs, ":" );
	if ( !token ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "connection string must contain username" );
		return NGX_CONF_ERROR;
	}

	len = cs_len - strlen(token);
	lcf->dbuser = ngx_pcalloc( cf->pool, len + 1 );
	if ( !lcf->dbuser ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "allocating memory" );
		return NGX_CONF_ERROR;
	}
	last = ngx_copy( lcf->dbuser, cs, len );
	*last = (u_char)'\0';

	cs = (u_char*)token + 1;
	cs_len = strlen(token) - 1;


	token = strstr( (const char *)cs, "@" );
	if ( !token ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "connection string must contain user password" );
		return NGX_CONF_ERROR;
	}
	
	len = cs_len - strlen(token);
	lcf->dbpass = ngx_pcalloc( cf->pool, len + 1 );
	if ( !lcf->dbpass ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "allocating memory" );
		return NGX_CONF_ERROR;
	}
	last = ngx_copy( lcf->dbpass, cs, len );
	*last = (u_char)'\0';

	cs = (u_char*)token + 1;
	cs_len = cs_len - len;


	/* check for host address */
	token = strstr( (const char *)cs, ":" );
	if ( !token ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "connection string must contain host address" );
		return NGX_CONF_ERROR;
	}
	
	len = cs_len - strlen(token) - 1;
	lcf->dbhost = ngx_pcalloc( cf->pool, len + 1 );
	if ( !lcf->dbhost ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "allocating memory" );
		return NGX_CONF_ERROR;
	}
	last = ngx_copy( lcf->dbhost, cs, len );
	*last = (u_char)'\0';

	cs = (u_char *)token + 1;
	cs_len = cs_len - len - 1;

	/* check for server port */
	token = strstr( (const char *)cs, "/" );
	if ( !token ) {
		ngx_log_error( NGX_LOG_ERR, cf->log, 0, "connection string must contain database port" );
		return NGX_CONF_ERROR;
	}
	
	len = cs_len - strlen(token) - 1;
	lcf->dbport = ngx_atoi( (u_char *)cs, len );

	return NGX_CONF_OK;
}

/*
 * Look for the client secret.
 *
 * 	@params:	*r				this http request structure;
 *				*con			a valid connection pointer to MySQL database;
 *				*client_id 		the string with API client id;
 *				*client_secret	this string will be filled with the client secret on success.
 *
 *	@return:	NGX_ERROR				on any internal error (null strings, memory allocation..etc.);
 *				NGX_HTTP_NOT_FOUND		if the query return no records;
 *				NGX_OK					on success;
 */
static ngx_int_t
ngx_apikey_mysql_fetch_client_secret( ngx_http_request_t *r, MYSQL *con, ngx_str_t *client_id, ngx_str_t *client_secret ) {

	MYSQL_RES 	*rs 	= NULL;
	MYSQL_ROW 	 row;

	char 		*sql = "SELECT secret FROM API_USER WHERE id = '%s'";

	char		 query[256];
	char		*fixed_client_id;

	u_char		*last	= NULL;

	if ( (client_id->data == NULL) || (con == NULL) ) 
		return NGX_ERROR;

	fixed_client_id = ngx_pcalloc( r->pool, client_id->len*2 );
	if ( !fixed_client_id ) {
		ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "allocating memory for client_id sql parameter" );
		return NGX_ERROR;
	}
	mysql_real_escape_string(con, fixed_client_id, (const char *)client_id->data, client_id->len );
	
	
	if( sprintf(query, sql, fixed_client_id) < 0 ) {
		ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "while formatting SQL: %s", sql );
		return NGX_ERROR;
	}
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql: %s", query );

	if( mysql_query(con, query) != 0 ) {
		ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "(%lu) - %s", mysql_errno(con), mysql_error(con) );
		return NGX_ERROR;	
	}

	rs = mysql_store_result( con );
	if ( rs == NULL ) {
		ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "(%lu) - %s", mysql_errno(con), mysql_error(con) );
		return NGX_ERROR;
	}

	row = mysql_fetch_row( rs );
	if ( mysql_num_rows(rs) != 1 ) {
		mysql_free_result(rs);
		return NGX_HTTP_NOT_FOUND;
	}
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "api secret for client <%s>: %s", fixed_client_id, row[0] );

	client_secret->len = ngx_strlen( row[0] );
	client_secret->data = ngx_pcalloc( r->pool, client_secret->len + 1 );
	if ( client_secret->data == NULL ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) failed allocating memory", __func__ );
		mysql_free_result(rs);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	last = (u_char *)ngx_copy( client_secret->data, row[0], client_secret->len );
	*last = (u_char)'\0';

	mysql_free_result(rs);

	return NGX_OK;
}


/**
 * Create the expire_time string as unix epoch adding the specified minutes.
 *
 *  @params:	*pool			pool for allocating memory;
 *				minutes_to_add	minute sto add to current time;
 *				*expire_time	the string which will containt the calculated expire_time
 *
 * @return:		NGX_ERROR		on error;
 *				NGX_OK			on success;
 */
static ngx_int_t
ngx_apikey_token_expire_time( ngx_pool_t *pool, size_t minutes_to_add, ngx_str_t *expire_time ) {
	//struct tm 	*lc_tm = NULL;

	uint8_t *last 	= NULL;
	uint8_t *buffer = NULL;


	time_t t;
    t = time(NULL);
	t += ( 60 * minutes_to_add ); //.Aggiungo i minuti
/*
	lc_tm = localtime( &t );
	if ( lc_tm == NULL ) {
        //fprintf( stderr, "%s::failed allocating localtime\n", __func__ );
        return NGX_ERROR;
    }
*/
 
	buffer = ngx_pcalloc(pool, NGX_INT_T_LEN + 1);
	if (buffer == NULL) {
		return NGX_ERROR;
	}

	
	expire_time->len = ngx_sprintf(buffer, "%ui", t) - buffer;
	expire_time->data = ngx_pcalloc(pool, expire_time->len + 1);
	if (expire_time->data == NULL) {
		return NGX_ERROR;
	}

	last = ngx_copy( expire_time->data, buffer, expire_time->len );
	*last = '\0';

	return NGX_OK;
}

/**
 *	Verify the request token digest.
 *
 *		digest = HMAC_SHA1( EXPIRE_TIME|REQUEST_URI, client_secret )
 *
 *	@params:	*r				this http request;
 *				*client_id		API client id;
 *				*issued_time	the request issued time (unix epoch);
 *				*client_digest	the digest from the request token;
 *
 *	@return		NGX_DECLINE		if verification fails;
 *				NGX_OK			on success;
 *
 */
static ngx_int_t
ngx_apikey_verify( ngx_http_request_t *r, ngx_str_t *client_id, ngx_str_t *issued_time, ngx_str_t *client_digest ) {

	ngx_int_t	rc;

	ngx_str_t	computed_digest		= ngx_null_string;
	ngx_str_t	message				= ngx_null_string;
	ngx_str_t	client_secret		= ngx_null_string;
	ngx_str_t	expire_time			= ngx_null_string;


	ngx_apikey_access_filter_loc_conf_t  *lcf = NULL;

	MYSQL	*con = NULL;
	
	u_char *last = NULL;


	lcf = ngx_http_get_module_loc_conf(r, ngx_apikey_access_filter_module);
    if ( !lcf->enable ) {
		return NGX_OK;
    }

	
	rc = ngx_apikey_token_expire_time(r->pool, lcf->expire_time, &expire_time);
	if ( rc != NGX_OK ) {
		return NGX_ERROR;	
	}
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "expire time -->: %V", &expire_time );
	
	if ( ngx_strcmp(issued_time->data, expire_time.data) > 0 ) {
		ngx_log_error( NGX_LOG_WARN, r->connection->log, 0, 
			"token issued time <%V> expired <%V>", issued_time, &expire_time );
		return NGX_ERROR;
	}
	
	//.Init MySQL connection object.	
	con = mysql_init( NULL );
	if ( con == NULL ) {
		ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "connecting to mysql" );
		return NGX_ERROR;
	}

	//.Connect to the specified MySQL database.
	if( !mysql_real_connect(
			con, 
			(const char *)lcf->dbhost, 
			(const char *)lcf->dbuser, 
			(const char *)lcf->dbpass, 
			(const char *)lcf->dbschema, 
			lcf->dbport, NULL,0) ) { 
		ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "Failed to connect to database: Error: %s", mysql_error(con) );
		return NGX_ERROR;
	}

	//.Fetch the client secret.
	rc = ngx_apikey_mysql_fetch_client_secret( r, con, client_id, &client_secret );
	if ( rc != NGX_OK ) {
		mysql_close( con );
		return NGX_DECLINED;
	}
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "client secret fetched: %V", &client_secret );

	//.Close the database connection and free the allocated memory.
	mysql_close( con );

	//.Compute the token digest.
	message.len = issued_time->len + 1 + r->uri.len;
	message.data = ngx_pcalloc( r->pool, message.len + 1 );
	if ( message.data == NULL ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "(%s) failed allocating memory", __func__ );
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	last = (u_char *)ngx_copy( message.data, issued_time->data, issued_time->len );
	*last++ = '|';
	last = (u_char *)ngx_copy( last, r->uri.data, r->uri.len );
	*last = (u_char)'\0';

	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "message: %V", &message );

	rc = ngx_apikey_hamac_sha1_digest( r->pool, &client_secret, &message, &computed_digest );
	if ( rc != NGX_OK ) {
		return NGX_DECLINED;
	}
	ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "calculated digest: %V", &computed_digest );

	//.Compare the digest from the request and the calculated digest.
	if ( ngx_strcmp(computed_digest.data, client_digest->data) != 0 ) {
		return NGX_DECLINED;	
	}

	return NGX_OK;
}


/*
 * Calculate the HMAC-SHA1 digest for a specified message with a defined key.
 *
 *	@parameters:	*pool		pool for memory allocation;
 *					*key		the hmac key;
 *					*message	the message to digest;
 *	
 *	@return	NGX_ERROR 	on error
 *			NGX_OK		on success
 */
static ngx_int_t
ngx_apikey_hamac_sha1_digest( ngx_pool_t *pool, ngx_str_t *key, ngx_str_t *message, ngx_str_t *digest ) {

	ngx_str_t	hmac_digest		= ngx_null_string;

	u_char		*last			= NULL;
	

	hmac_digest.len 	= EVP_MAX_MD_SIZE;
	hmac_digest.data = ngx_pcalloc( pool, EVP_MAX_MD_SIZE );
	if ( hmac_digest.data == NULL ) {
		ngx_log_error(NGX_LOG_ERR, pool->log, 0, "(%s) failed allocating memory", __func__ );
        return NGX_ERROR;
	}

	/*
	HMAC_CTX ctx;
	HMAC_Init( &ctx, key->data, sizeof(key->data), EVP_sha1() );
	HMAC_Update(&ctx,  message->data, sizeof(message->data));
 	HMAC_Final(&ctx, hmac_digest.data, &hmac_digest.len );		
	HMAC_cleanup(&ctx);
	*/
	
	last = HMAC (EVP_sha1 (), 
		(const void *)key->data, (int)key->len, 
		message->data, (int)message->len, 
		hmac_digest.data, (unsigned int *)&hmac_digest.len );

	if ( last == NULL ) {
		ngx_pfree( pool, hmac_digest.data );
		ngx_log_error(NGX_LOG_ERR, pool->log, 0, "(%s) failed calculating HMAC digest", __func__ );
        return NGX_ERROR;
	}
	
	digest->len  = EVP_MAX_MD_SIZE*2;
	digest->data = ngx_pcalloc( pool, digest->len + 1 );
    if ( digest->data == NULL ) {
		ngx_pfree( pool, hmac_digest.data );
		ngx_log_error(NGX_LOG_ERR, pool->log, 0, "(%s) failed allocating memory", __func__ );
        return NGX_ERROR;
	}
	
	ngx_hex_dump(digest->data, hmac_digest.data, hmac_digest.len);
	

	ngx_pfree( pool, hmac_digest.data );

	
	return NGX_OK;
}

/**
 * Brute force search for one header with the specified name.
 */
static ngx_table_elt_t *
ngx_apikey_find_request_header(ngx_http_request_t *r, u_char *name, size_t len) {

    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;
 
    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &r->headers_in.headers.part;
    h = part->elts;
 
    /*
    Headers list array may consist of more than one part,
    so loop through all of it
    */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }
 
            part = part->next;
            h = part->elts;
            i = 0;
        }
 
        /*
        Just compare the lengths and then the names case insensitively.
        */
		//ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "found request header ( %s ) with value ( %s )", h[i].key.data, h[i].value.data );

        if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }
 
        /*
        Ta-da, we got one!
        Note, we'v stop the search at the first matched header
        while more then one header may fit.
        */
        return &h[i];
    }
 
    /*
    No headers was found
    */
    return NULL;
}

