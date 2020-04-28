#ifndef redirectionio_protocol_h
#define redirectionio_protocol_h

#include "mod_redirectionio.h"
#include "httpd.h"

#define REDIRECTIONIO_PROTOCOL_VERSION_MAJOR 1
#define REDIRECTIONIO_PROTOCOL_VERSION_MINOR 0

#define REDIRECTIONIO_PROTOCOL_COMMAND_MATCH_ACTION 0
#define REDIRECTIONIO_PROTOCOL_COMMAND_LOG 1

apr_status_t redirectionio_protocol_match(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key);
apr_status_t redirectionio_protocol_log(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key);
apr_status_t redirectionio_protocol_send_filter_headers(redirectionio_context *ctx, request_rec *r);

#endif
