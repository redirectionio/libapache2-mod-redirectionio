#include "redirectionio_protocol.h"
#include "http_log.h"
#include "json.h"
#include "apr_strings.h"

static char errbuf[1024];

const char COMMAND_MATCH_NAME[] = "MATCH_WITH_RESPONSE";
const char COMMAND_MATCH_QUERY[] = "{ \"project_id\": \"%s\", \"request_uri\": \"%s\", \"host\": \"%s\" }";
const char COMMAND_LOG_NAME[] = "LOG";
const char COMMAND_LOG_QUERY[] = "{ \"project_id\": \"%s\", \"request_uri\": \"%s\", \"host\": \"%s\", \"rule_id\": \"%s\", \"target\": \"%s\", \"status_code\": %d, \"user_agent\": \"%s\", \"referer\": \"%s\" }";

static apr_status_t redirectionio_read_json_handler(redirectionio_connection *conn, apr_pool_t *pool, cJSON **json);

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

    cJSON *status = cJSON_GetObjectItem(result, "status_code");
    cJSON *match_on_response_status = cJSON_GetObjectItem(result, "match_on_response_status");
    cJSON *location = cJSON_GetObjectItem(result, "location");
    cJSON *matched_rule = cJSON_GetObjectItem(result, "matched_rule");
    cJSON *rule_id = NULL;

    if (matched_rule != NULL && matched_rule->type != cJSON_NULL) {
        rule_id = cJSON_GetObjectItem(matched_rule, "id");
    }

    if (matched_rule == NULL || matched_rule->type == cJSON_NULL) {
        ctx->matched_rule_id = "";
        ctx->status = 0;
        ctx->match_on_response_status = 0;

        return APR_SUCCESS;
    }

    ctx->matched_rule_id = rule_id->valuestring;
    ctx->target = location->valuestring;
    ctx->status = status->valueint;
    ctx->match_on_response_status = 0;

    if (match_on_response_status != NULL && match_on_response_status->type != cJSON_NULL) {
        ctx->match_on_response_status = match_on_response_status->valueint;
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

static apr_status_t redirectionio_json_cleanup(void *data) {
    cJSON_Delete((cJSON *)data);

    return APR_SUCCESS;
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
