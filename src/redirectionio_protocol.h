#ifndef redirectionio_protocol_h
#define redirectionio_protocol_h

#include "mod_redirectionio.h"
#include "httpd.h"

apr_status_t redirectionio_protocol_match(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key);
apr_status_t redirectionio_protocol_log(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key);
apr_status_t redirectionio_protocol_send_filter_headers(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key);
apr_status_t redirectionio_protocol_send_filter_body_init(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key);
apr_status_t redirectionio_protocol_send_filter_body_chunk(redirectionio_connection *conn, const char *input, uint64_t input_size, const char **output, uint64_t *output_size, apr_pool_t *pool);
apr_status_t redirectionio_protocol_send_filter_body_finish(redirectionio_connection *conn, const char **output, uint64_t *output_size, apr_pool_t *pool);

#endif
