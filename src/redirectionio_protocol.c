#include "redirectionio_protocol.h"
#include "http_log.h"
#include "json.h"
#include "apr_strings.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

static char errbuf[1024];

const char COMMAND_MATCH_NAME[] = "MATCH_RULE";
const char COMMAND_MATCH_QUERY[] = "{ \"project_id\": \"%s\", \"request_uri\": \"%s\", \"host\": \"%s\" }";
const char COMMAND_LOG_NAME[] = "LOG";
const char COMMAND_LOG_QUERY[] = "{ \"project_id\": \"%s\", \"request_uri\": \"%s\", \"host\": \"%s\", \"rule_id\": \"%s\", \"target\": \"%s\", \"status_code\": %d, \"user_agent\": \"%s\", \"referer\": \"%s\", \"method\": \"%s\", \"proxy\": \"%s\" }";

static apr_status_t redirectionio_read_json_handler(redirectionio_connection *conn, apr_pool_t *pool, cJSON **json, char **json_str);

apr_status_t redirectionio_protocol_match(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_size_t      wlen, clen;
    char            *dst;
    apr_status_t    rv;
    cJSON           *result;
    char            *result_str;

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

    rv = redirectionio_read_json_handler(conn, r->pool, &result, &result_str);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error receiving match command result: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    ctx->matched_rule_str = result_str;
    ctx->matched_rule = result;

    return APR_SUCCESS;
}

apr_status_t redirectionio_protocol_log(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_size_t      wlen, clen;
    const char      *location;
    const char      *user_agent = apr_table_get(r->headers_in, "User-Agent");
    const char      *referer = apr_table_get(r->headers_in, "Referer");
    cJSON           *matched_rule_id;
    char            *rule_id_str = NULL;
    apr_status_t    rv;
    char            *dst;
    request_rec     *response = r;

    // Only trust last response for data
    while (response->next) {
        response = response->next;
    }

    location = apr_table_get(response->headers_out, "Location");

    if (location == NULL) {
        location = "";
    }

    if (user_agent == NULL) {
        user_agent = "";
    }

    if (referer == NULL) {
        referer = "";
    }

    if (ctx->matched_rule != NULL) {
        matched_rule_id = cJSON_GetObjectItem(ctx->matched_rule, "id");

        if (matched_rule_id != NULL) {
            rule_id_str = matched_rule_id->valuestring;
        }
    }

    if (rule_id_str == NULL) {
        rule_id_str = "";
    }

    wlen =
        sizeof(COMMAND_LOG_QUERY)
        + strlen(project_key)
        + strlen(r->unparsed_uri)
        + strlen(r->hostname)
        + strlen(rule_id_str)
        + strlen(location)
        + 3 // Status code length
        + strlen(user_agent)
        + strlen(referer)
        + strlen(r->method)
        + strlen(PROXY_VERSION_STR(PROXY_VERSION))
        - 20 // 10 * 2 (%x) characters replaced with values
    ;

    dst = (char *) apr_palloc(r->pool, wlen);

    sprintf(
        dst,
        COMMAND_LOG_QUERY,
        project_key,
        r->unparsed_uri,
        r->hostname,
        rule_id_str,
        location,
        response->status,
        user_agent,
        referer,
        r->method,
        PROXY_VERSION_STR(PROXY_VERSION)
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

apr_status_t redirectionio_protocol_send_filter_headers(redirectionio_context *ctx, request_rec *r) {
    const apr_array_header_t    *tarr = apr_table_elts(r->headers_out);
    const apr_table_entry_t     *telts = (const apr_table_entry_t*)tarr->elts;
    cJSON                       *headers, *new_headers, *header, *item, *name, *value;
    int                         i;
    char                        *headers_str, *new_headers_str, *name_str, *value_str;

    headers = cJSON_CreateArray();

     for (i = 0; i < tarr->nelts; i++) {
        header = cJSON_CreateObject();
        cJSON_AddItemToObject(header, "name", cJSON_CreateString((const char *)telts[i].key));
        cJSON_AddItemToObject(header, "value", cJSON_CreateString((const char *)telts[i].val));

        cJSON_AddItemToArray(headers, header);
    }

    headers_str = cJSON_PrintUnformatted(headers);
    new_headers_str = (char *)redirectionio_header_filter(ctx->matched_rule_str, headers_str);
    cJSON_Delete(headers);
    free(headers_str);

    if (new_headers_str == NULL) {
        return APR_SUCCESS;
    }

    new_headers = cJSON_Parse(new_headers_str);

    if (new_headers == NULL || new_headers->type != cJSON_Array) {
        free(new_headers_str);

        return APR_SUCCESS;
    }

    apr_table_clear(r->headers_out);
    item = new_headers->child;

    while (item != NULL) {
        // Item is a header
        name = cJSON_GetObjectItem(item, "name");
        value = cJSON_GetObjectItem(item, "value");
        item = item->next;

        if (name == NULL || value == NULL || name->type != cJSON_String || value->type != cJSON_String) {
            continue;
        }

        name_str = apr_pstrdup(r->pool, name->valuestring);
        value_str = apr_pstrdup(r->pool, value->valuestring);

        apr_table_setn(r->headers_out, name_str, value_str);
    }

    cJSON_Delete(new_headers);
    free(new_headers_str);

    return APR_SUCCESS;
}

static apr_status_t redirectionio_json_cleanup(void *data) {
    cJSON_Delete((cJSON *)data);

    return APR_SUCCESS;
}

static apr_status_t redirectionio_read_json_handler(redirectionio_connection *conn, apr_pool_t *pool, cJSON **json, char **json_str) {
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
            *json_str = (char *)(buffer - len);

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
