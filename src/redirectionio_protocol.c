#include "redirectionio_protocol.h"
#include "http_log.h"
#include "json.h"
#include "apr_strings.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

static char errbuf[1024];

const char COMMAND_MATCH_NAME[] = "MATCH_WITH_RESPONSE";
const char COMMAND_MATCH_QUERY[] = "{ \"project_id\": \"%s\", \"request_uri\": \"%s\", \"host\": \"%s\" }";
const char COMMAND_LOG_NAME[] = "LOG";
const char COMMAND_LOG_QUERY[] = "{ \"project_id\": \"%s\", \"request_uri\": \"%s\", \"host\": \"%s\", \"rule_id\": \"%s\", \"target\": \"%s\", \"status_code\": %d, \"user_agent\": \"%s\", \"referer\": \"%s\" }";
const char COMMAND_FILTER_HEADER_NAME[] = "FILTER_HEADER";
const char COMMAND_FILTER_BODY_NAME[] = "FILTER_BODY";

static apr_status_t redirectionio_read_json_handler(redirectionio_connection *conn, apr_pool_t *pool, cJSON **json);
static apr_status_t redirectionio_write_string(redirectionio_connection *conn, const char* data);

apr_status_t redirectionio_protocol_match(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_size_t      wlen, clen;
    char            *dst;
    apr_status_t    rv;
    cJSON           *result;

    wlen = sizeof(COMMAND_MATCH_QUERY) + strlen(project_key) + strlen(r->unparsed_uri) + strlen(r->hostname) - 6;
    dst = (char *) apr_palloc(r->pool, wlen);
    sprintf(dst, COMMAND_MATCH_QUERY, project_key, r->unparsed_uri, r->hostname);

    clen = sizeof(COMMAND_MATCH_NAME);
    rv = apr_socket_send(conn->rio_sock, COMMAND_MATCH_NAME, &clen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending match command: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = apr_socket_send(conn->rio_sock, dst, &wlen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending match command data: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = redirectionio_read_json_handler(conn, r->pool, &result);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error receiving match command result: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    ctx->should_filter_body = 0;
    ctx->should_filter_headers = 0;
    ctx->matched_rule_id = "";
    ctx->status = 0;
    ctx->match_on_response_status = 0;

    cJSON *status = cJSON_GetObjectItem(result, "status_code");
    cJSON *match_on_response_status = cJSON_GetObjectItem(result, "match_on_response_status");
    cJSON *location = cJSON_GetObjectItem(result, "location");
    cJSON *matched_rule = cJSON_GetObjectItem(result, "matched_rule");
    cJSON *should_filter_headers = cJSON_GetObjectItem(result, "should_filter_headers");
    cJSON *should_filter_body = cJSON_GetObjectItem(result, "should_filter_body");
    cJSON *rule_id = NULL;

    if (matched_rule != NULL && matched_rule->type != cJSON_NULL) {
        rule_id = cJSON_GetObjectItem(matched_rule, "id");
    }

    if (matched_rule == NULL || matched_rule->type == cJSON_NULL) {
        return APR_SUCCESS;
    }

    ctx->matched_rule_id = rule_id->valuestring;
    ctx->target = location->valuestring;
    ctx->status = status->valueint;

    if (match_on_response_status != NULL && match_on_response_status->type != cJSON_NULL) {
        ctx->match_on_response_status = match_on_response_status->valueint;
    }

    if (should_filter_headers != NULL && should_filter_headers->type == cJSON_True) {
        ctx->should_filter_headers = 1;
    }

    if (should_filter_body != NULL && should_filter_body->type == cJSON_True) {
        ctx->should_filter_body = 1;
    }

    return APR_SUCCESS;
}

apr_status_t redirectionio_protocol_log(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_size_t      wlen, clen;
    const char      *location = apr_table_get(r->headers_out, "Location");
    const char      *user_agent = apr_table_get(r->headers_in, "User-Agent");
    const char      *referer = apr_table_get(r->headers_in, "Referer");
    const char      *matched_rule_id = ctx->matched_rule_id;
    apr_status_t    rv;
    char            *dst;

    if (location == NULL) {
        location = "";
    }

    if (user_agent == NULL) {
        user_agent = "";
    }

    if (referer == NULL) {
        referer = "";
    }

    if (matched_rule_id == NULL) {
        matched_rule_id = "";
    }

    wlen =
        sizeof(COMMAND_LOG_QUERY)
        + strlen(project_key)
        + strlen(r->unparsed_uri)
        + strlen(r->hostname)
        + strlen(matched_rule_id)
        + strlen(location)
        + 3 // Status code length
        + strlen(user_agent)
        + strlen(referer)
        - 16 // 8 * 2 (%x) characters replaced with values
    ;

    dst = (char *) apr_palloc(r->pool, wlen);

    sprintf(
        dst,
        COMMAND_LOG_QUERY,
        project_key,
        r->unparsed_uri,
        r->hostname,
        matched_rule_id,
        location,
        r->status,
        user_agent,
        referer
    );

    clen = sizeof(COMMAND_LOG_NAME);
    rv = apr_socket_send(conn->rio_sock, COMMAND_LOG_NAME, &clen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending log command: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = apr_socket_send(conn->rio_sock, dst, &wlen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending log command data: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    return APR_SUCCESS;
}

apr_status_t redirectionio_protocol_send_filter_headers(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_size_t                  wlen, clen;
    const apr_array_header_t    *tarr = apr_table_elts(r->headers_out);
    const apr_table_entry_t     *telts = (const apr_table_entry_t*)tarr->elts;
    cJSON                       *query, *headers, *header, *item, *name, *value;
    int                         i;
    const char                  *dst;
    apr_status_t                rv;
    cJSON                       *result;

    query = cJSON_CreateObject();
    headers = cJSON_CreateArray();

    cJSON_AddItemToObject(query, "project_id", cJSON_CreateString(project_key));
    cJSON_AddItemToObject(query, "rule_id", cJSON_CreateString(ctx->matched_rule_id));
    cJSON_AddItemToObject(query, "headers", headers);

     for (i = 0; i < tarr->nelts; i++) {
        header = cJSON_CreateObject();
        cJSON_AddItemToObject(header, "name", cJSON_CreateString((const char *)telts[i].key));
        cJSON_AddItemToObject(header, "value", cJSON_CreateString((const char *)telts[i].val));

        cJSON_AddItemToArray(headers, header);
    }

    dst = cJSON_PrintUnformatted(query);

    clen = sizeof(COMMAND_FILTER_HEADER_NAME);
    rv = apr_socket_send(conn->rio_sock, COMMAND_FILTER_HEADER_NAME, &clen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending filter headers command: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    wlen = strlen(dst) + 1;
    rv = apr_socket_send(conn->rio_sock, dst, &wlen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending filter headers command data: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = redirectionio_read_json_handler(conn, r->pool, &result);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error receiving filter headers command result: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    headers = cJSON_GetObjectItem(result, "headers");

    if (headers == NULL || headers->type != cJSON_Array) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: No headers present int json result");

        return APR_EINCOMPLETE;
    }

    apr_table_clear(r->headers_out);
    item = headers->child;

    while (item != NULL) {
        // Item is a header
        name = cJSON_GetObjectItem(item, "name");
        value = cJSON_GetObjectItem(item, "value");
        item = item->next;

        if (name == NULL || value == NULL || name->type != cJSON_String || value->type != cJSON_String) {
            continue;
        }

        apr_table_setn(r->headers_out, name->valuestring, value->valuestring);
    }

    return APR_SUCCESS;
}

apr_status_t redirectionio_protocol_send_filter_body_init(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_size_t                  clen;
    apr_status_t                rv;

    clen = sizeof(COMMAND_FILTER_BODY_NAME);
    rv = apr_socket_send(conn->rio_sock, COMMAND_FILTER_BODY_NAME, &clen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending filter body command: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = redirectionio_write_string(conn, project_key);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending filter body project key: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = redirectionio_write_string(conn, ctx->matched_rule_id);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending filter body rule id: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    return APR_SUCCESS;
}

apr_status_t redirectionio_protocol_send_filter_body_chunk(redirectionio_connection *conn, const char *input, uint64_t input_size, const char **output, int64_t *output_size, apr_pool_t *pool) {
    apr_size_t      llen;
    apr_status_t    rv;
    uint64_t        length;

    llen = sizeof(uint64_t);
    length = htonll(input_size);
    // Send buffer
    rv = apr_socket_send(conn->rio_sock, (const char *)&length, &llen);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Error sending filter body chunk size: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = apr_socket_send(conn->rio_sock, input, &input_size);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Error sending filter body chunk data: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    // Receive filtered one
    rv = apr_socket_recv(conn->rio_sock, (char *)output_size, &llen);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Error receiving filter body chunk size: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    *output_size = ntohll(*output_size);

    if (*output_size <= 0) {
        return APR_SUCCESS;
    }

    *output = (const char *) apr_palloc(pool, *output_size);
    rv = apr_socket_recv(conn->rio_sock, (char *)*output, (apr_size_t *)output_size);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Error receiving filter body chunk data: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    return APR_SUCCESS;
}

apr_status_t redirectionio_protocol_send_filter_body_finish(redirectionio_connection *conn, const char **output, int64_t *output_size, apr_pool_t *pool) {
    apr_size_t      llen;
    apr_status_t    rv;
    int64_t         length, dummy;

    // Send buffer
    llen = sizeof(int64_t);
    length = -1;
    rv = apr_socket_send(conn->rio_sock, (const char *)&length, &llen);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Error sending filter body chunk size: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    // Receive filtered one
    rv = apr_socket_recv(conn->rio_sock, (char *)output_size, &llen);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Error receiving filter body chunk size: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    *output_size = ntohll(*output_size);

    if (*output_size < 0) {
        return APR_SUCCESS;
    }

    if (*output_size > 0) {
        *output = (const char *) apr_palloc(pool, *output_size);
        rv = apr_socket_recv(conn->rio_sock, (char *)*output, (apr_size_t *)output_size);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Error receiving filter body chunk data: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

            return rv;
        }
    }

    apr_socket_recv(conn->rio_sock, (char *)&dummy, &llen);

    return APR_SUCCESS;
}

static apr_status_t redirectionio_json_cleanup(void *data) {
    cJSON_Delete((cJSON *)data);

    return APR_SUCCESS;
}

static apr_status_t redirectionio_write_string(redirectionio_connection *conn, const char* data) {
    apr_size_t      llen, slen;
    uint64_t        length;
    apr_status_t    rv;

    llen = sizeof(uint64_t);
    slen = strlen(data);
    length = htonll(slen);

    rv = apr_socket_send(conn->rio_sock, (const char *)&length, &llen);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    return apr_socket_send(conn->rio_sock, data, &slen);
}

static apr_status_t redirectionio_read_json_handler(redirectionio_connection *conn, apr_pool_t *pool, cJSON **json) {
    apr_size_t      rlen = 1;
    apr_size_t      len = 0;
    apr_size_t      max_size = 8192;
    apr_status_t    rs;
    char            *buffer;
    char            read;

    buffer = (char *) apr_palloc(pool, max_size);

    for (;;) {
        rlen = 1;
        rs = apr_socket_recv(conn->rio_sock, &read, &rlen);

        if (rs != APR_SUCCESS) { /* Error */
            return rs;
        }

        if (rlen != 1 || len > max_size) { /* Too big */
            return APR_EOF;
        }

        if (read == '\0') { /* Message readed, push it to the current handler */
            if (len == 0) {
                continue;
            }

            *buffer = '\0';
            *json = cJSON_Parse((char *)(buffer - len));

            if (*json == NULL) {
                return APR_EOF;
            }

            apr_pool_cleanup_register(
                pool,
                *json,
                redirectionio_json_cleanup,
                apr_pool_cleanup_null
            );

            return APR_SUCCESS;
        }

        len++;
        *buffer = read;
        buffer++;
    }
}
