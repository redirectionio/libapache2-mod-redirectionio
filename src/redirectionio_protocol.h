#ifndef redirectionio_protocol_h
#define redirectionio_protocol_h

#include "mod_redirectionio.h"
#include "httpd.h"

apr_status_t redirectionio_protocol_match(redirectionio_context *ctx, request_rec *r, const char *project_key);
apr_status_t redirectionio_protocol_log(redirectionio_context *ctx, request_rec *r, const char *project_key);

#endif
