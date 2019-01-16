#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_network_io.h"
#include "apr_strings.h"
#include "apr_uri.h"
#include "mod_redirectionio.h"
#include "redirectionio_protocol.h"

static char errbuf[1024];

static void redirectionio_register_hooks(apr_pool_t *p);

static void ap_headers_insert_output_filter(request_rec *r);

static int redirectionio_match_handler(request_rec *r);
static int redirectionio_redirect_handler(request_rec *r);
static int redirectionio_log_handler(request_rec *r);

static apr_status_t redirectionio_filter_match_on_response(ap_filter_t *f, apr_bucket_brigade *b);
static apr_status_t redirectionio_filter_header_filtering(ap_filter_t *f, apr_bucket_brigade *b);
static apr_status_t redirectionio_filter_body_filtering(ap_filter_t *f, apr_bucket_brigade *b);

static apr_status_t redirectionio_create_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool);
static redirectionio_connection* redirectionio_acquire_connection(redirectionio_config *config, apr_pool_t *pool);
static apr_status_t redirectionio_release_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool);
static apr_status_t redirectionio_invalidate_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool);

static void *create_redirectionio_dir_conf(apr_pool_t *pool, char *context);
static void *merge_redirectionio_dir_conf(apr_pool_t *pool, void *BASE, void *ADD);

static apr_status_t redirectionio_pool_construct(void** rs, void* params, apr_pool_t* pool);
static apr_status_t redirectionio_pool_destruct(void* resource, void* params, apr_pool_t* pool);
static apr_status_t redirectionio_child_exit(void *resource);

static const char *redirectionio_set_enable(cmd_parms *cmd, void *cfg, const char *arg);
static const char *redirectionio_set_project_key(cmd_parms *cmd, void *cfg, const char *arg);
static const char *redirectionio_set_logs_enable(cmd_parms *cmd, void *cfg, const char *arg);
static const char *redirectionio_set_pass(cmd_parms *cmd, void *cfg, const char *arg);

static const command_rec redirectionio_directives[] = {
    AP_INIT_TAKE1("redirectionio", redirectionio_set_enable, NULL, OR_ALL, "Enable or disable redirectionio"),
    AP_INIT_TAKE1("redirectionioPass", redirectionio_set_pass, NULL, OR_ALL, "Agent server location"),
    AP_INIT_TAKE1("redirectionioProjectKey", redirectionio_set_project_key, NULL, OR_ALL, "RedirectionIO project key"),
    AP_INIT_TAKE1("redirectionioLogs", redirectionio_set_logs_enable, NULL, OR_ALL, "Enable or disable logging for redirectionio"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA redirectionio_module = {
    STANDARD20_MODULE_STUFF,
    create_redirectionio_dir_conf, /* create per-dir    config structures */
    merge_redirectionio_dir_conf, /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    redirectionio_directives, /* table of config file commands       */
    redirectionio_register_hooks  /* register hooks                      */
};

static void redirectionio_register_hooks(apr_pool_t *p) {
    ap_hook_type_checker(redirectionio_match_handler, NULL, NULL, APR_HOOK_LAST);

    ap_hook_handler(redirectionio_redirect_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_log_transaction(redirectionio_log_handler, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_insert_filter(ap_headers_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_insert_error_filter(ap_headers_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
    ap_register_output_filter("redirectionio_redirect_filter", redirectionio_filter_match_on_response, NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter("redirectionio_header_filter", redirectionio_filter_header_filtering, NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter("redirectionio_body_filter", redirectionio_filter_body_filtering, NULL, AP_FTYPE_CONTENT_SET);
}

static int redirectionio_match_handler(request_rec *r) {
    redirectionio_config *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);

    if (config->enable != 1) {
        return DECLINED;
    }

    // Create context
    redirectionio_context   *ctx = ap_get_module_config(r->request_config, &redirectionio_module);

    if (ctx != NULL) {
        return DECLINED;
    }

    ctx = apr_palloc(r->pool, sizeof(redirectionio_context));

    if (ctx == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redirectionio: cannot create context, skipping module");

        return DECLINED;
    }

    ctx->status = 0;
    ctx->match_on_response_status = 0;
    ctx->is_redirected = 0;
    ctx->should_filter_body = 0;
    ctx->should_filter_headers = 0;
    ctx->body_filter_conn = NULL;

    ap_set_module_config(r->request_config, &redirectionio_module, ctx);
    redirectionio_connection* conn = redirectionio_acquire_connection(config, r->pool);

    if (conn == NULL) {
        return DECLINED;
    }

    // Ask for redirection
    if (redirectionio_protocol_match(conn, ctx, r, config->project_key) != APR_SUCCESS) {
        redirectionio_invalidate_connection(conn, config, r->pool);

        return DECLINED;
    }

    redirectionio_release_connection(conn, config, r->pool);

    return APR_SUCCESS;
}

static void ap_headers_insert_output_filter(request_rec *r) {
    redirectionio_config    *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);
    redirectionio_context   *ctx = ap_get_module_config(r->request_config, &redirectionio_module);

    if (config->enable != 1) {
        return;
    }

    if (ctx == NULL) {
        return;
    }

    if (ctx->status != 0 && ctx->match_on_response_status != 0 && !ctx->is_redirected && r->status == ctx->match_on_response_status) {
        ap_add_output_filter("redirectionio_redirect_filter", ctx, r, r->connection);
    }

    if (ctx->should_filter_headers == 1) {
        ap_add_output_filter("redirectionio_header_filter", ctx, r, r->connection);
    }

    if (ctx->should_filter_body == 1) {
        ap_add_output_filter("redirectionio_body_filter", ctx, r, r->connection);
    }
}

static int redirectionio_redirect_handler(request_rec *r) {
    redirectionio_config    *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);

    // Not enabled
    if (config->enable != 1) {
        return DECLINED;
    }

    redirectionio_context   *ctx = ap_get_module_config(r->request_config, &redirectionio_module);

    // No match here
    if (ctx->status == 0 || ctx->is_redirected == 1) {
        return DECLINED;
    }

    if (ctx->match_on_response_status > 0) {
        return DECLINED;
    }

    if (ctx->status != 410) {
        apr_table_setn(r->headers_out, "Location", ctx->target);
    }

    r->status = ctx->status;
    ctx->is_redirected = 1;

    return ctx->status;
}

static apr_status_t redirectionio_filter_match_on_response(ap_filter_t *f, apr_bucket_brigade *bb) {
    redirectionio_context   *ctx = (redirectionio_context *)f->ctx;

    if (ctx->status != 410) {
        apr_table_setn(f->r->headers_out, "Location", ctx->target);
    }

    f->r->status = ctx->status;
    ctx->is_redirected = 1;

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, bb);
}

static apr_status_t redirectionio_filter_header_filtering(ap_filter_t *f, apr_bucket_brigade *bb) {
    redirectionio_context   *ctx = (redirectionio_context *)f->ctx;
    redirectionio_config    *config = (redirectionio_config*) ap_get_module_config(f->r->per_dir_config, &redirectionio_module);

    ap_remove_output_filter(f);

    // Get connection
    redirectionio_connection* conn = redirectionio_acquire_connection(config, f->r->pool);

    if (conn == NULL) {
        return ap_pass_brigade(f->next, bb);;
    }

    // Send headers
    if (redirectionio_protocol_send_filter_headers(conn, ctx, f->r, config->project_key) != APR_SUCCESS) {
        redirectionio_invalidate_connection(conn, config, f->r->pool);

        return ap_pass_brigade(f->next, bb);;
    }

    redirectionio_release_connection(conn, config, f->r->pool);

    return ap_pass_brigade(f->next, bb);
}

static apr_status_t redirectionio_filter_body_filtering(ap_filter_t *f, apr_bucket_brigade *bb) {
    redirectionio_context   *ctx = (redirectionio_context *)f->ctx;
    redirectionio_config    *config = (redirectionio_config*) ap_get_module_config(f->r->per_dir_config, &redirectionio_module);
    apr_bucket              *b, *b_new;
    apr_bucket_brigade      *bb_new;
    const char              *input, *output;
    int64_t                 input_size, output_size;
    apr_status_t            rv;

    // If first -> remove content_length, get_connection, init filtering command
    if (ctx->body_filter_conn == NULL) {
        ctx->body_filter_conn = redirectionio_acquire_connection(config, f->r->pool);

        if (ctx->body_filter_conn == NULL) {
            ap_remove_output_filter(f);

            return ap_pass_brigade(f->next, bb);
        }

        if (redirectionio_protocol_send_filter_body_init(ctx->body_filter_conn, ctx, f->r, config->project_key) != APR_SUCCESS) {
            redirectionio_invalidate_connection(ctx->body_filter_conn, config, f->r->pool);
            ap_remove_output_filter(f);

            return ap_pass_brigade(f->next, bb);
        }

        // Force chunked encoding
        apr_table_unset(f->r->headers_out, "Content-Length");
    }

    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    bb_new = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    b = APR_BRIGADE_FIRST(bb);

    // filter brigade
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        // Read bucket
        rv = apr_bucket_read(b, &input, (apr_size_t *)&input_size, APR_BLOCK_READ);

        if (rv != APR_SUCCESS) {
            redirectionio_invalidate_connection(ctx->body_filter_conn, config, f->r->pool);
            ap_remove_output_filter(f);

            return ap_pass_brigade(f->next, bb);
        }

        // Send bucket
        if (input_size > 0) {
            rv = redirectionio_protocol_send_filter_body_chunk(ctx->body_filter_conn, input, input_size, &output, &output_size, f->r->pool);

            if (rv != APR_SUCCESS) {
                redirectionio_invalidate_connection(ctx->body_filter_conn, config, f->r->pool);
                ap_remove_output_filter(f);

                return ap_pass_brigade(f->next, bb);
            }

            // Create a new one
            if (output_size > 0) {
                b_new = apr_bucket_transient_create(output, output_size, f->r->connection->bucket_alloc);

                if (b_new == NULL) {
                    redirectionio_invalidate_connection(ctx->body_filter_conn, config, f->r->pool);
                    ap_remove_output_filter(f);

                    return ap_pass_brigade(f->next, bb);
                }

                // Append it to the new brigade
                APR_BRIGADE_INSERT_TAIL(bb_new, b_new);
            }
        }

        if (APR_BUCKET_IS_EOS(b)) {
            // Send termination to the connection and wait for it to return us the last data
            rv = redirectionio_protocol_send_filter_body_finish(ctx->body_filter_conn, &output, &output_size, f->r->pool);

            if (rv != APR_SUCCESS) {
                redirectionio_invalidate_connection(ctx->body_filter_conn, config, f->r->pool);
                ap_remove_output_filter(f);

                return ap_pass_brigade(f->next, bb);
            }

            if (output_size > 0) {
                // Create a new one
                b_new = apr_bucket_transient_create(output, output_size, f->r->connection->bucket_alloc);

                if (b_new == NULL) {
                    redirectionio_invalidate_connection(ctx->body_filter_conn, config, f->r->pool);
                    ap_remove_output_filter(f);

                    return ap_pass_brigade(f->next, bb);
                }

                // Append it to the new brigade
                APR_BRIGADE_INSERT_TAIL(bb_new, b_new);
            }

            // Create also an eos bucket and append it to the brigade
            b_new = apr_bucket_eos_create(f->r->connection->bucket_alloc);

            if (b_new == NULL) {
                redirectionio_invalidate_connection(ctx->body_filter_conn, config, f->r->pool);
                ap_remove_output_filter(f);

                return ap_pass_brigade(f->next, bb);
            }

            APR_BRIGADE_INSERT_TAIL(bb_new, b_new);

            // Release connection
            redirectionio_release_connection(ctx->body_filter_conn, config, f->r->pool);

            // Remove filter
            ap_remove_output_filter(f);

            // Break
            break;
        }

        b = APR_BUCKET_NEXT(b);
    }

    // Clear old brigade and buckets
    apr_brigade_destroy(bb);

    // Pass new brigade and buckets to the next filter
    return ap_pass_brigade(f->next, bb_new);
}

static int redirectionio_log_handler(request_rec *r) {
    redirectionio_config *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);

    if (config->enable != 1) {
        return DECLINED;
    }

    if (config->enable_logs != 1) {
        return DECLINED;
    }

    redirectionio_context* context = ap_get_module_config(r->request_config, &redirectionio_module);

    if (context == NULL) {
        return DECLINED;
    }

    redirectionio_connection* conn = redirectionio_acquire_connection(config, r->pool);

    if (conn == NULL) {
        return DECLINED;
    }

    if (redirectionio_protocol_log(conn, context, r, config->project_key) != APR_SUCCESS) {
        redirectionio_invalidate_connection(conn, config, r->pool);

        return DECLINED;
    }

    redirectionio_release_connection(conn, config, r->pool);

    return OK;
}

static apr_status_t redirectionio_create_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool) {
    apr_status_t    rv;
    apr_int32_t     family = APR_INET;

    if (config->protocol == UNIX) {
        family = APR_UNIX;
    }

    rv = apr_sockaddr_info_get(&conn->rio_addr, config->server, family, config->port, 0, pool);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: apr_sockaddr_info_get failed %s:%d %s", config->server, config->port, apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = apr_socket_create(&conn->rio_sock, conn->rio_addr->family, SOCK_STREAM, APR_PROTO_TCP, pool);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error opening socket: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = apr_socket_connect(conn->rio_sock, conn->rio_addr);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error connecting to redirection io agent: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    /* set socket options */
    rv = apr_socket_opt_set(conn->rio_sock, APR_SO_NONBLOCK, 0);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error setting socket to blocking: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = apr_socket_opt_set(conn->rio_sock, APR_TCP_NODELAY, 1);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error setting socket TCP nodelay: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    rv = apr_socket_timeout_set(conn->rio_sock, RIO_TIMEOUT);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error setting socket timeout: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    return APR_SUCCESS;
}

static redirectionio_connection* redirectionio_acquire_connection(redirectionio_config *config, apr_pool_t *pool) {
    apr_status_t                rv;
    redirectionio_connection    *conn;

    rv = apr_reslist_acquire(config->connection_pool, (void**)&conn);

    if (rv != APR_SUCCESS || !conn) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Failed to acquire RIO connection from pool: %s",  apr_strerror(rv, errbuf, sizeof(errbuf)));

        return NULL;
    }

    return conn;
}

static apr_status_t redirectionio_release_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool) {
    apr_status_t rv = apr_reslist_release(config->connection_pool, conn);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Can not release RIO socket.");
    }

    return rv;
}

static apr_status_t redirectionio_invalidate_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool) {
    apr_status_t rv = apr_reslist_invalidate(config->connection_pool, conn);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Can not invalidate RIO socket.");
    }

    return rv;
}

static void *create_redirectionio_dir_conf(apr_pool_t *pool, char *context) {
    redirectionio_config    *config = apr_pcalloc(pool, sizeof(redirectionio_config));

    context = context ? context : "(undefined context)";

    if (config) {
        config->enable = -1;
        config->enable_logs = -1;
        config->server = NULL;
        config->project_key = NULL;
        config->protocol = -1;
        config->port = -1;
    }

    return config;
}

static void *merge_redirectionio_dir_conf(apr_pool_t *pool, void *parent, void *current) {
    redirectionio_config    *conf_parent = (redirectionio_config *) parent;
    redirectionio_config    *conf_current = (redirectionio_config *) current;
    redirectionio_config    *conf = (redirectionio_config *) create_redirectionio_dir_conf(pool, "Merged configuration");

    /* Merge configurations */
    if (conf_current->enable == -1) {
        conf->enable = conf_parent->enable;
    } else {
        conf->enable = conf_current->enable;
    }

    if (conf_current->enable_logs == -1) {
        conf->enable_logs = conf_parent->enable_logs;
    } else {
        conf->enable_logs = conf_current->enable_logs;
    }

    if (conf_current->project_key == NULL) {
        conf->project_key = conf_parent->project_key;
    } else {
        conf->project_key = conf_current->project_key;
    }

    if (conf_current->server == NULL) {
        conf->port = conf_parent->port;
        conf->protocol = conf_parent->protocol;
        conf->server = conf_parent->server;
    } else {
        conf->port = conf_current->port;
        conf->protocol = conf_current->protocol;
        conf->server = conf_current->server;
    }

    if (apr_reslist_create(
        &conf->connection_pool,
        RIO_MIN_CONNECTIONS,
        RIO_KEEP_CONNECTIONS,
        RIO_MAX_CONNECTIONS,
        0,
        redirectionio_pool_construct,
        redirectionio_pool_destruct,
        conf,
        pool
    ) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool, "mod_redirectionio: Failed to initialize resource pool, disabling redirectionio.");

        conf->enable = 0;

        return conf;
    }

    apr_reslist_timeout_set(conf->connection_pool, RIO_TIMEOUT);
    apr_pool_cleanup_register(pool, conf->connection_pool, redirectionio_child_exit, redirectionio_child_exit);

    return conf;
}

static apr_status_t redirectionio_pool_construct(void** rs, void* params, apr_pool_t* pool) {
    redirectionio_config        *conf = (redirectionio_config *) params;
    redirectionio_connection    *conn;
    apr_status_t                rv;

    if (conf->enable != 1) {
        return APR_SUCCESS;
    }

    conn = apr_palloc(pool, sizeof(redirectionio_connection));
    rv = redirectionio_create_connection(conn, conf, pool);

    if (rv != APR_SUCCESS) {
        return APR_EGENERAL;
    }

    *rs = conn;

    if (!*rs) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool, "mod_redirectionio: Failed to store socket in resource list");

        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static apr_status_t redirectionio_pool_destruct(void* resource, void* params, apr_pool_t* pool) {
    if (resource) {
        redirectionio_connection *conn = (redirectionio_connection*)resource;
        apr_socket_close(conn->rio_sock);
    }

    return APR_SUCCESS;
}

static apr_status_t redirectionio_child_exit(void *resource) {
    apr_reslist_t   *connection_pool = (apr_reslist_t *)resource;
    apr_pool_t      *pool;
    apr_pool_create(&pool, NULL);

    while (apr_reslist_acquired_count(connection_pool) != 0) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Socket pool not empty: %i", apr_reslist_acquired_count(connection_pool));
    }

    apr_reslist_destroy(connection_pool);

    return APR_SUCCESS;
}

static const char *redirectionio_set_enable(cmd_parms *cmd, void *cfg, const char *arg) {
    redirectionio_config *conf = (redirectionio_config*)cfg;

    if (conf) {
        if(!strcasecmp(arg, "on")) {
            conf->enable = 1;

            if (conf->enable_logs == -1) {
                conf->enable_logs = 1;
            }
        } else {
            conf->enable = 0;
        }
    }

    return NULL;
}

static const char *redirectionio_set_project_key(cmd_parms *cmd, void *cfg, const char *arg) {
    redirectionio_config *conf = (redirectionio_config*)cfg;

    if (conf) {
        conf->project_key = arg;

        if (strlen(conf->project_key) > 0 && conf->enable == -1) {
            conf->enable = 1;

            if (conf->enable_logs == -1) {
                conf->enable_logs = 1;
            }
        }
    }

    return NULL;
}

static const char *redirectionio_set_logs_enable(cmd_parms *cmd, void *cfg, const char *arg) {
    redirectionio_config *conf = (redirectionio_config*)cfg;

    if (conf) {
        if(!strcasecmp(arg, "on")) {
            conf->enable_logs = 1;
        } else {
            conf->enable_logs = 0;
        }
    }

    return NULL;
}

static const char *redirectionio_set_pass(cmd_parms *cmd, void *cfg, const char *arg) {
    apr_uri_t               uri;
    redirectionio_config    *conf = (redirectionio_config*)cfg;

    if (apr_uri_parse(cmd->pool, arg, &uri) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Could not parse agent url %s, disable module.", arg);
        conf->enable = 0;

        return NULL;
    }

    if (uri.scheme != NULL && apr_strnatcmp(uri.scheme, "unix") == 0) {
        conf->protocol = UNIX;
    }

    if (uri.scheme != NULL && apr_strnatcmp(uri.scheme, "tcp") == 0) {
        conf->protocol = TCP;
    }

    if (conf->protocol != UNIX && conf->protocol != TCP) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Server protocol is %s, but must be 'unix://' or 'tcp://', disable module.", uri.scheme);
        conf->enable = 0;
    }

    if (conf->protocol == UNIX && uri.path) {
        conf->server = uri.path;
    }

    if (conf->protocol == TCP && uri.hostname) {
        conf->server = uri.hostname;
    }

    if (uri.port) {
        conf->port = uri.port;
    }

    return NULL;
}
