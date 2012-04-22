
/*
 * Copyright (C) 2012 Luca Sepe
 */


#ifndef _NGX_APIKEY_ACCESS_FILTER_H_INCLUDED_
#define _NGX_APIKEY_ACCESS_FILTER_H_INCLUDED_


/* 
 * Module Configuration Struct [ngx_http_<module name>_(main|srv|loc)_conf_t] 
 */
typedef struct {
	ngx_flag_t	 enable;

	ngx_uint_t	 expire_time;

	u_char 		*dbuser;
	u_char 		*dbpass;
	u_char 		*dbhost;
	u_char 		*dbschema;
	ngx_uint_t 	 dbport;
	
} ngx_apikey_access_filter_loc_conf_t;



extern ngx_module_t  ngx_apikey_access_filter_module;

#endif /* _NGX_APIKEY_ACCESS_FILTER_H_INCLUDED_ */

