nginx_apikey_access_filter_module
=================================

Nginx filter to restrict the access at your backend APIs

Status
======

This module is under active development.

Synopsis
========

      # let's filter all the requests to our backend API s(i.e. a tornado web app)
      location ~* \.do$ {

         # enable the apikey access filter
         apikey_access_filter on;

         # set the connection string for the client_id / client_secret provider
         apikey_access_filter_dburl "mysql://apikeyadmin:apikeyadmin@127.0.0.1:3306/APIKEYS";

         # common reverse proxy config (i.e. for tornado)         
         proxy_pass_header Server;
         proxy_set_header Host $http_host;                                                                                                           
         proxy_redirect off;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Scheme $scheme;
         proxy_pass http://backends;
      }


Description
===========

