#include "redirectionio_protocol.h"
#include "http_log.h"
#include "apr_strings.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

static char errbuf[1024];

const char COMMAND_LOG_QUERY[] = "{ \"project_id\": \"%s\", \"request_uri\": \"%s\", \"host\": \"%s\", \"rule_id\": \"%s\", \"target\": \"%s\", \"status_code\": %d, \"user_agent\": \"%s\", \"referer\": \"%s\", \"method\": \"%s\", \"proxy\": \"%s\" }";

static apr_status_t redirectionio_send_uint8(redirectionio_connection *conn, unsigned char uint8);

static apr_status_t redirectionio_send_uint16(redirectionio_connection *conn, apr_uint16_t uint16);

static apr_status_t redirectionio_send_uint32(redirectionio_connection *conn, apr_uint32_t uint32);

static apr_status_t redirectionio_send_string(redirectionio_connection *conn, const char *string, apr_size_t buf_size);

static apr_status_t redirectionio_read_uint32(redirectionio_connection *conn, apr_uint32_t *uint32);

static apr_status_t redirectionio_read_string(redirectionio_connection *conn, char *string, apr_size_t buf_size);

static apr_status_t redirectionio_send_protocol_header(redirectionio_connection *conn, const char *project_key, apr_uint16_t command, request_rec *r);

apr_status_t redirectionio_protocol_match(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_uint32_t                    alen;
    apr_status_t                    rv;
    struct REDIRECTIONIO_Request    *redirectionio_request;
    struct REDIRECTIONIO_HeaderMap  *first_header = NULL, *current_header = NULL;
    const char                      *request_serialized;
    char                            *action_serialized;
    const apr_array_header_t        *tarr = apr_table_elts(r->headers_in);
    const apr_table_entry_t         *telts = (const apr_table_entry_t*)tarr->elts;
    int                             i;

    // Create request header map
    for (i = 0; i < tarr->nelts; i++) {
        current_header = (struct REDIRECTIONIO_HeaderMap *) apr_palloc(r->pool, sizeof(struct REDIRECTIONIO_HeaderMap));

        if (current_header == NULL) {
            return APR_EGENERAL;
        }

        current_header->name = (const char *)telts[i].key;
        current_header->value = (const char *)telts[i].val;
        current_header->next = first_header;

        first_header = current_header;
    }

    // Create redirection io request
    redirectionio_request = (struct REDIRECTIONIO_Request *)redirectionio_request_create(r->unparsed_uri, r->method, first_header);

    if (redirectionio_request == NULL) {
        return APR_EGENERAL;
    }

    // Serialize request
    request_serialized = redirectionio_request_json_serialize(redirectionio_request);

    if (request_serialized == NULL) {
        return APR_EGENERAL;
    }

    // Send protocol header
    rv = redirectionio_send_protocol_header(conn, project_key, REDIRECTIONIO_PROTOCOL_COMMAND_MATCH_ACTION, r);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    // Send serialized request length
    rv = redirectionio_send_uint32(conn, strlen(request_serialized));

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending request length: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    // Send serialized request
    rv = redirectionio_send_string(conn, request_serialized, strlen(request_serialized));

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending request: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    // Read action length
    rv = redirectionio_read_uint32(conn, &alen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error recv action length: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    // Read action
    action_serialized = apr_palloc(r->pool, alen);

    if (action_serialized == NULL) {
        return APR_EGENERAL;
    }

    if (alen > 0) {
        rv = redirectionio_read_string(conn, action_serialized, alen);

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error recv action: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

            return rv;
        }

        // Unserialize action
        ctx->action = (struct REDIRECTIONIO_Action *)redirectionio_action_json_deserialize(action_serialized);
    }

    return APR_SUCCESS;
}

apr_status_t redirectionio_protocol_log(redirectionio_connection *conn, redirectionio_context *ctx, request_rec *r, const char *project_key) {
    apr_size_t      wlen;
    const char      *location;
    const char      *user_agent = apr_table_get(r->headers_in, "User-Agent");
    const char      *referer = apr_table_get(r->headers_in, "Referer");
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

    // Send protocol header
    rv = redirectionio_send_protocol_header(conn, project_key, REDIRECTIONIO_PROTOCOL_COMMAND_LOG, r);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = redirectionio_send_uint32(conn, wlen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending log command length: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

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
    const apr_array_header_t        *tarr = apr_table_elts(r->headers_out);
    const apr_table_entry_t         *telts = (const apr_table_entry_t*)tarr->elts;
    int                             i;
    char                            *name_str, *value_str;
    struct REDIRECTIONIO_HeaderMap  *first_header = NULL, *current_header = NULL;

    // Create request header map
    for (i = 0; i < tarr->nelts; i++) {
        current_header = (struct REDIRECTIONIO_HeaderMap *) apr_palloc(r->pool, sizeof(struct REDIRECTIONIO_HeaderMap));

        if (current_header == NULL) {
            return APR_EGENERAL;
        }

        current_header->name = (const char *)telts[i].key;
        current_header->value = (const char *)telts[i].val;
        current_header->next = first_header;

        first_header = current_header;
    }

    first_header = (struct REDIRECTIONIO_HeaderMap *)redirectionio_action_header_filter_filter(ctx->action, first_header, r->status);

    // Even if error returns success, as it does not affect anything
    if (first_header == NULL) {
        return APR_SUCCESS;
    }

    apr_table_clear(r->headers_out);

    while (first_header != NULL) {
        if (first_header->name != NULL && first_header->value != NULL) {
            name_str = apr_pstrdup(r->pool, first_header->name);
            value_str = apr_pstrdup(r->pool, first_header->value);

            apr_table_setn(r->headers_out, name_str, value_str);
        }

        first_header = first_header->next;
    }

    // @TODO DROP Header map

    return APR_SUCCESS;
}

static apr_status_t redirectionio_send_uint8(redirectionio_connection *conn, unsigned char uint8) {
    apr_size_t  slen = sizeof(unsigned char);

    return apr_socket_send(conn->rio_sock, (char *)&uint8, &slen);
}

static apr_status_t redirectionio_send_uint16(redirectionio_connection *conn, apr_uint16_t uint16) {
    apr_status_t    rv;
    apr_size_t      srlen = sizeof(apr_uint16_t);
    apr_size_t      serlen = sizeof(apr_uint16_t);
    apr_size_t      sdrlen = 0;

    uint16 = htons(uint16);

    while (sdrlen < serlen) {
        rv = apr_socket_send(conn->rio_sock, (char *)(&uint16 + sdrlen), &srlen);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        sdrlen += srlen;
        srlen = serlen - sdrlen;
    }

    return APR_SUCCESS;
}

static apr_status_t redirectionio_send_uint32(redirectionio_connection *conn, apr_uint32_t uint32) {
    apr_status_t    rv;
    apr_size_t      srlen = sizeof(apr_uint32_t);
    apr_size_t      serlen = sizeof(apr_uint32_t);
    apr_size_t      sdrlen = 0;

    uint32 = htonl(uint32);

    while (sdrlen < serlen) {
        rv = apr_socket_send(conn->rio_sock, (char *)(&uint32 + sdrlen), &srlen);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        sdrlen += srlen;
        srlen = serlen - sdrlen;
    }

    return APR_SUCCESS;
}

static apr_status_t redirectionio_send_string(redirectionio_connection *conn, const char *string, apr_size_t buf_size) {
    apr_status_t    rv;
    apr_size_t      srlen = buf_size;
    apr_size_t      sdrlen = 0;

    while (sdrlen < buf_size) {
        rv = apr_socket_send(conn->rio_sock, (char *)(string + sdrlen), &srlen);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        sdrlen += srlen;
        srlen = buf_size - sdrlen;
    }

    return APR_SUCCESS;
}

static apr_status_t redirectionio_read_uint32(redirectionio_connection *conn, apr_uint32_t *uint32) {
    apr_status_t    rv;
    apr_size_t      srlen = sizeof(apr_uint32_t);
    apr_size_t      serlen = sizeof(apr_uint32_t);
    apr_size_t      sdrlen = 0;

    while (sdrlen < serlen) {
        rv = apr_socket_recv(conn->rio_sock, (char *)(uint32 + sdrlen), &srlen);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        sdrlen += srlen;
        srlen = serlen - sdrlen;
    }

    *uint32 = ntohl(*uint32);

    return APR_SUCCESS;
}

static apr_status_t redirectionio_read_string(redirectionio_connection *conn, char *string, apr_size_t buf_size) {
    apr_status_t    rv;
    apr_size_t      srlen = buf_size;
    apr_size_t      sdrlen = 0;

    while (sdrlen < buf_size) {
        rv = apr_socket_recv(conn->rio_sock, (char *)(string + sdrlen), &srlen);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        sdrlen += srlen;
        srlen = buf_size - sdrlen;
    }

    return APR_SUCCESS;
}

static apr_status_t redirectionio_send_protocol_header(redirectionio_connection *conn, const char *project_key, apr_uint16_t command, request_rec *r) {
    apr_status_t    rv;

    // Send protocol major version
    rv = redirectionio_send_uint8(conn, REDIRECTIONIO_PROTOCOL_VERSION_MAJOR);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending protocol major version: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    // Send protocol minor version
    rv = redirectionio_send_uint8(conn, REDIRECTIONIO_PROTOCOL_VERSION_MINOR);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending protocol minor version: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    if (strlen(project_key) > 255) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Size of token cannot exceed 255 characters");

        return APR_EGENERAL;
    }

    // Send project key length
    unsigned char project_key_len = (unsigned char)strlen(project_key);
    rv = redirectionio_send_uint8(conn, project_key_len);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending project key length: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = redirectionio_send_string(conn, project_key, strlen(project_key));

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending project key: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = redirectionio_send_uint16(conn, command);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: Error sending command: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    return APR_SUCCESS;
}

