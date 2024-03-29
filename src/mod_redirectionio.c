#include "mod_redirectionio.h"
#include "redirectionio_protocol.h"

static char errbuf[1024];

static void redirectionio_register_hooks(apr_pool_t *p);

static void ap_headers_insert_output_filter(request_rec *r);

static int redirectionio_match_handler(request_rec *r);
static int redirectionio_redirect_handler(request_rec *r);
static int redirectionio_log_handler(request_rec *r);

static int redirectionio_redirect_handler_for_status_code(request_rec *r);

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
static const char *redirectionio_set_scheme(cmd_parms *cmd, void *cfg, const char *arg);
static const char *redirectionio_set_show_rule_ids(cmd_parms *cmd, void *cfg, const char *arg);
static const char *redirectionio_set_server(cmd_parms *cmd, void *dc, int argc, char *const argv[]);
static const char *redirectionio_set_header(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
static const char *redirectionio_set_trusted_proxies(cmd_parms *cmd, void *cfg, const char *arg);
static void redirectionio_apache_log_callback(const char* log_str, const void* data, short level);
static apr_status_t redirectionio_atoi(const char *line, apr_size_t len);

static const command_rec redirectionio_directives[] = {
    AP_INIT_TAKE1("redirectionio", redirectionio_set_enable, NULL, OR_ALL, "Enable or disable redirectionio"),
    AP_INIT_TAKE_ARGV("redirectionioPass", redirectionio_set_server, NULL, OR_ALL, "Agent server location"),
    AP_INIT_TAKE1("redirectionioProjectKey", redirectionio_set_project_key, NULL, OR_ALL, "RedirectionIO project key"),
    AP_INIT_TAKE1("redirectionioLogs", redirectionio_set_logs_enable, NULL, OR_ALL, "Enable or disable logging for redirectionio"),
    AP_INIT_TAKE1("redirectionioScheme", redirectionio_set_scheme, NULL, OR_ALL, "Force scheme to use when matching request"),
    AP_INIT_TAKE1("redirectionioRuleIdsHeader", redirectionio_set_show_rule_ids, NULL, OR_ALL, "Show rule ids used on response header"),
    AP_INIT_TAKE2("redirectionioSetHeader", redirectionio_set_header, NULL, OR_ALL, "Add header to match in redirectionio request"),
    AP_INIT_TAKE1("redirectionioTrustedProxies", redirectionio_set_trusted_proxies, NULL, OR_ALL, "Trusted proxies to filter client ip"),
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
    ap_hook_type_checker(redirectionio_match_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(redirectionio_match_handler, NULL, NULL, APR_HOOK_FIRST);

    ap_hook_handler(redirectionio_redirect_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(redirectionio_log_handler, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_insert_filter(ap_headers_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_insert_error_filter(ap_headers_insert_output_filter, NULL, NULL, APR_HOOK_LAST);

    ap_register_output_filter("REDIRECTIONIO_REDIRECT_FILTER", redirectionio_filter_match_on_response, NULL, AP_FTYPE_CONTENT_SET - 1);
    ap_register_output_filter("REDIRECTIONIO_HEADER_FILTER", redirectionio_filter_header_filtering, NULL, AP_FTYPE_CONTENT_SET - 1);
    ap_register_output_filter("REDIRECTIONIO_BODY_FILTER", redirectionio_filter_body_filtering, NULL, AP_FTYPE_CONTENT_SET - 1);
}

static int redirectionio_match_handler(request_rec *r) {
    redirectionio_config *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);

    if (config->enable != 1) {
        return DECLINED;
    }

    // Do not match against internal redirect
    if (r->prev) {
        return DECLINED;
    }

    if (config->connection_pool == NULL) {
        if (apr_reslist_create(
            &config->connection_pool,
            config->server.min_conns,
            config->server.keep_conns,
            config->server.max_conns,
            0,
            redirectionio_pool_construct,
            redirectionio_pool_destruct,
            config,
            config->pool
        ) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "mod_redirectionio: Failed to initialize resource pool, disabling redirectionio.");

            config->enable = 0;

            return DECLINED;
        }

        apr_reslist_timeout_set(config->connection_pool, config->server.timeout * 1000);
        apr_pool_cleanup_register(config->pool, config->connection_pool, redirectionio_child_exit, redirectionio_child_exit);
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

    apr_pool_pre_cleanup_register(r->pool, ctx, redirectionio_context_cleanup);

    ctx->request = NULL;
    ctx->action = NULL;
    ctx->response_headers = NULL;
    ctx->body_filter = NULL;
    ctx->backend_response_status_code = 0;

    ap_set_module_config(r->request_config, &redirectionio_module, ctx);
    redirectionio_connection* conn = redirectionio_acquire_connection(config, r->pool);

    if (conn == NULL) {
        return DECLINED;
    }

    // Init logging
    redirectionio_log_init_with_callback(redirectionio_apache_log_callback, r);

    // Ask for redirection
    if (redirectionio_protocol_match(conn, ctx, r, config->project_key) != APR_SUCCESS) {
        redirectionio_invalidate_connection(conn, config, r->pool);

        return DECLINED;
    }

    redirectionio_release_connection(conn, config, r->pool);

    return DECLINED;
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

    ap_add_output_filter("REDIRECTIONIO_REDIRECT_FILTER", ctx, r, r->connection);
    ap_add_output_filter("REDIRECTIONIO_HEADER_FILTER", ctx, r, r->connection);
    ap_add_output_filter("REDIRECTIONIO_BODY_FILTER", ctx, r, r->connection);
}

static int redirectionio_redirect_handler_for_status_code(request_rec *r) {
    apr_uint16_t            new_status_code;
    redirectionio_config    *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);

    // Not enabled
    if (config->enable != 1) {
        return DECLINED;
    }

    redirectionio_context   *ctx = ap_get_module_config(r->request_config, &redirectionio_module);

    if (ctx == NULL) {
        return DECLINED;
    }

    // No match here
    if (ctx->action == NULL) {
        return DECLINED;
    }

    new_status_code = redirectionio_action_get_status_code(ctx->action, ctx->backend_response_status_code);

    if (new_status_code == 0) {
        return DECLINED;
    }

    r->status = new_status_code;

    if (ctx->backend_response_status_code == 0) {
        r->handler = "redirectionio";
        r->filename = "redirectionio";
    }

    return r->status;
}

static int redirectionio_redirect_handler(request_rec *r) {
    redirectionio_context   *ctx = ap_get_module_config(r->request_config, &redirectionio_module);

    if (ctx == NULL) {
        return DECLINED;
    }

    ctx->backend_response_status_code = 0;

    return redirectionio_redirect_handler_for_status_code(r);
}

static apr_status_t redirectionio_filter_match_on_response(ap_filter_t *f, apr_bucket_brigade *bb) {
    redirectionio_context   *ctx = ap_get_module_config(f->r->request_config, &redirectionio_module);

    if (ctx == NULL) {
        return DECLINED;
    }

    ctx->backend_response_status_code = f->r->status;
    redirectionio_redirect_handler_for_status_code(f->r);

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, bb);
}

static apr_status_t redirectionio_filter_header_filtering(ap_filter_t *f, apr_bucket_brigade *bb) {
    redirectionio_context   *ctx = (redirectionio_context *)f->ctx;

    if (ctx == NULL) {
        return ap_pass_brigade(f->next, bb);
    }

    if (ctx->action == NULL) {
        return ap_pass_brigade(f->next, bb);
    }

    redirectionio_protocol_send_filter_headers(ctx, f->r);
    ap_remove_output_filter(f);

    if (ctx->body_filter == NULL) {
        ctx->body_filter = (struct REDIRECTIONIO_FilterBodyAction *)redirectionio_action_body_filter_create(ctx->action, ctx->backend_response_status_code, ctx->response_headers);

        // Force chunked encoding
        if (ctx->body_filter != NULL) {
            apr_table_unset(f->r->headers_out, "Content-Length");
        }
    }

    return ap_pass_brigade(f->next, bb);
}

static apr_status_t redirectionio_filter_body_filtering(ap_filter_t *f, apr_bucket_brigade *bb) {
    redirectionio_context       *ctx = (redirectionio_context *)f->ctx;
    apr_bucket                  *b, *b_new;
    apr_bucket_brigade          *bb_new;
    const char                  *input_bucket;
    struct REDIRECTIONIO_Buffer input, output;
    apr_status_t                rv;

    if (ctx == NULL) {
        return ap_pass_brigade(f->next, bb);
    }

    if (ctx->body_filter == NULL) {
        ap_remove_output_filter(f);

        return ap_pass_brigade(f->next, bb);
    }

    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    bb_new = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    b = APR_BRIGADE_FIRST(bb);

    // filter brigade
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        // Read bucket
        rv = apr_bucket_read(b, &input_bucket, (apr_size_t *)&input.len, APR_BLOCK_READ);

        if (rv != APR_SUCCESS) {
            redirectionio_action_body_filter_drop(ctx->body_filter);
            ctx->body_filter = NULL;
            ap_remove_output_filter(f);

            return ap_pass_brigade(f->next, bb);
        }

        // Send bucket
        if (input.len > 0) {
            input.data = malloc(input.len);
            memcpy(input.data, input_bucket, input.len);

            output = redirectionio_action_body_filter_filter(ctx->body_filter, input);

            // Create a new one
            if (output.len > 0) {
                b_new = apr_bucket_transient_create((const char *)output.data, output.len, f->r->connection->bucket_alloc);

                if (b_new == NULL) {
                    redirectionio_action_body_filter_drop(ctx->body_filter);
                    ctx->body_filter = NULL;
                    ap_remove_output_filter(f);
                    free(output.data);

                    return ap_pass_brigade(f->next, bb);
                }

                // Append it to the new brigade
                APR_BRIGADE_INSERT_TAIL(bb_new, b_new);
            }
        }

        if (APR_BUCKET_IS_EOS(b)) {
            output = redirectionio_action_body_filter_close(ctx->body_filter);
            ctx->body_filter = NULL;
            ap_remove_output_filter(f);

            if (output.len > 0) {
                // Create a new one
                b_new = apr_bucket_transient_create((const char *)output.data, output.len, f->r->connection->bucket_alloc);

                if (b_new == NULL) {
                    free(output.data);

                    return ap_pass_brigade(f->next, bb);
                }

                // Append it to the new brigade
                APR_BRIGADE_INSERT_TAIL(bb_new, b_new);
            }

            // Create also an eos bucket and append it to the brigade
            b_new = apr_bucket_eos_create(f->r->connection->bucket_alloc);

            if (b_new == NULL) {
                return ap_pass_brigade(f->next, bb);
            }

            APR_BRIGADE_INSERT_TAIL(bb_new, b_new);

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
    bool                 should_log;
    redirectionio_config *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);
    request_rec          *response = r;

    if (config->enable != 1) {
        return DECLINED;
    }

    redirectionio_context* context = ap_get_module_config(r->request_config, &redirectionio_module);

    if (context == NULL) {
        return DECLINED;
    }

    // Only trust last response for data
    while (response->next) {
        response = response->next;
    }

    should_log = redirectionio_action_should_log_request(context->action, config->enable_logs == 1, context->backend_response_status_code);

    if (!should_log) {
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

    if (config->server.protocol == UNIX) {
        family = APR_UNIX;
    }

    rv = apr_sockaddr_info_get(&conn->rio_addr, config->server.pass, family, config->server.port, 0, pool);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: apr_sockaddr_info_get failed %s:%d %s", config->server.pass, config->server.port, apr_strerror(rv, errbuf, sizeof(errbuf)));

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

    rv = apr_socket_opt_set(conn->rio_sock, APR_SO_KEEPALIVE, 1);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error setting socket keepalive: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

        return rv;
    }

    if (config->server.protocol == TCP) {
        rv = apr_socket_opt_set(conn->rio_sock, APR_TCP_NODELAY, 1);

        if (rv != APR_SUCCESS) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error setting socket TCP nodelay: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));

            return rv;
        }
    }

    rv = apr_socket_timeout_set(conn->rio_sock, config->server.timeout * 1000);

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
        config->project_key = NULL;
        config->scheme = NULL;
        config->server.protocol = TCP;
        config->server.pass = "127.0.0.1";
        config->server.pass_set = -1;
        config->server.port = 10301;
        config->server.min_conns = RIO_MIN_CONNECTIONS;
        config->server.max_conns = RIO_MAX_CONNECTIONS;
        config->server.keep_conns = RIO_KEEP_CONNECTIONS;
        config->server.timeout = RIO_TIMEOUT;
        config->pool = pool;
        config->show_rule_ids = -1;
        config->headers_set = NULL;
        config->trusted_proxies = NULL;
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

    if (conf_current->headers_set == NULL) {
        conf->headers_set = conf_parent->headers_set;
    } else if (conf_parent->headers_set == NULL) {
        conf->headers_set = conf_current->headers_set;
    } else {
        conf->headers_set = apr_table_overlay(pool, conf_current->headers_set, conf_parent->headers_set);
    }

    if (conf_current->enable_logs == -1) {
        conf->enable_logs = conf_parent->enable_logs;
    } else {
        conf->enable_logs = conf_current->enable_logs;
    }

    if (conf_current->show_rule_ids == -1) {
        conf->show_rule_ids = conf_parent->show_rule_ids;
    } else {
        conf->show_rule_ids = conf_current->show_rule_ids;
    }

    if (conf_current->project_key == NULL) {
        conf->project_key = conf_parent->project_key;
    } else {
        conf->project_key = conf_current->project_key;
    }

    if (conf_current->scheme == NULL) {
        conf->scheme = conf_parent->scheme;
    } else {
        conf->scheme = conf_current->scheme;
    }

    if (conf_current->server.pass_set == -1) {
        conf->server.port = conf_parent->server.port;
        conf->server.protocol = conf_parent->server.protocol;
        conf->server.pass = conf_parent->server.pass;
        conf->server.pass_set = conf_parent->server.pass_set;
        conf->server.min_conns = conf_parent->server.min_conns;
        conf->server.max_conns = conf_parent->server.max_conns;
        conf->server.keep_conns = conf_parent->server.keep_conns;
        conf->server.timeout = conf_parent->server.timeout;
    } else {
        conf->server.port = conf_current->server.port;
        conf->server.protocol = conf_current->server.protocol;
        conf->server.pass = conf_current->server.pass;
        conf->server.pass_set = conf_current->server.pass_set;
        conf->server.min_conns = conf_current->server.min_conns;
        conf->server.max_conns = conf_current->server.max_conns;
        conf->server.keep_conns = conf_current->server.keep_conns;
        conf->server.timeout = conf_current->server.timeout;
    }

    if (conf_current->trusted_proxies == NULL) {
        conf->trusted_proxies = conf_parent->trusted_proxies;
    } else {
        conf->trusted_proxies = conf_current->trusted_proxies;
    }

    conf->pool = pool;
    conf->connection_pool = NULL;

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

            if (conf->show_rule_ids == -1) {
                conf->show_rule_ids = 0;
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

static const char *redirectionio_set_scheme(cmd_parms *cmd, void *cfg, const char *arg) {
    redirectionio_config *conf = (redirectionio_config*)cfg;

    if (conf) {
        conf->scheme = arg;
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

static const char *redirectionio_set_show_rule_ids(cmd_parms *cmd, void *cfg, const char *arg) {
    redirectionio_config *conf = (redirectionio_config*)cfg;

    if (conf) {
        if(!strcasecmp(arg, "on")) {
            conf->show_rule_ids = 1;
        } else {
            conf->show_rule_ids = 0;
        }
    }

    return NULL;
}

static const char *redirectionio_set_server(cmd_parms *cmd, void *cfg, int argc, char *const argv[]) {
    apr_uri_t               uri;
    redirectionio_config    *conf = (redirectionio_config*)cfg;
    const char              *server_pass;
    int                     i;
    size_t                  arg_len;

    if (argc < 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Could not parse agent server, no parameter, disable module.");
        conf->enable = 0;

        return NULL;
    }

    server_pass = argv[0];

    if (apr_uri_parse(cmd->pool, server_pass, &uri) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Could not parse agent url %s, disable module.", server_pass);
        conf->enable = 0;

        return NULL;
    }

    conf->server.pass_set = 1;

    if (uri.scheme != NULL && apr_strnatcmp(uri.scheme, "unix") == 0) {
        conf->server.protocol = UNIX;
    }

    if (uri.scheme != NULL && apr_strnatcmp(uri.scheme, "tcp") == 0) {
        conf->server.protocol = TCP;
    }

    if (conf->server.protocol != UNIX && conf->server.protocol != TCP) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: Server protocol is %s, but must be 'unix://' or 'tcp://', disable module.", uri.scheme);
        conf->enable = 0;
    }

    if (conf->server.protocol == UNIX && uri.path) {
        conf->server.pass = uri.path;
    }

    if (conf->server.protocol == TCP && uri.hostname) {
        conf->server.pass = uri.hostname;
    }

    if (uri.port) {
        conf->server.port = uri.port;
    }

    for (i = 1; i < argc; i++) {
        arg_len = strlen(argv[i]);

        if (strncasecmp(argv[i], "min_conns=", 10) == 0) {
            conf->server.min_conns = redirectionio_atoi(&argv[i][10], arg_len - 10);

            if (conf->server.min_conns == APR_EGENERAL) {
                goto invalid;
            }

            continue;
        }

        if (strncasecmp(argv[i], "max_conns=", 10) == 0) {
            conf->server.max_conns = redirectionio_atoi(&argv[i][10], arg_len - 10);

            if (conf->server.max_conns == APR_EGENERAL) {
                goto invalid;
            }

            continue;
        }

        if (strncasecmp(argv[i], "keep_conns=", 11) == 0) {
            conf->server.keep_conns = redirectionio_atoi(&argv[i][11], arg_len - 11);

            if (conf->server.keep_conns == APR_EGENERAL) {
                goto invalid;
            }

            continue;
        }

        if (strncasecmp(argv[i], "timeout=", 8) == 0) {
            conf->server.timeout = (apr_interval_time_t) redirectionio_atoi(&argv[i][8], arg_len - 8);

            if (conf->server.timeout == (apr_interval_time_t) APR_EGENERAL) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    return NULL;

invalid:
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redirectionio: invalid parameter when setting pass: %s.", argv[i]);
    conf->enable = 0;

    return NULL;
}

static const char *redirectionio_set_header(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2) {
    redirectionio_config *conf = (redirectionio_config*)cfg;

    if (conf->headers_set == NULL) {
        conf->headers_set = apr_table_make(conf->pool, 10);
    }

    apr_table_set(conf->headers_set, arg1, arg2);

    return NULL;
}

static const char *redirectionio_set_trusted_proxies(cmd_parms *cmd, void *cfg, const char *arg) {
    redirectionio_config *conf = (redirectionio_config*)cfg;

    if (conf) {
        conf->trusted_proxies = (struct REDIRECTIONIO_TrustedProxies *) redirectionio_trusted_proxies_create(arg);
    }

    return NULL;
}

static void redirectionio_apache_log_callback(const char* log_str, const void* data, short level) {
    if (level <= 1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, (request_rec *)data, "mod_redirectionio api error: %s", log_str);
    }

    free((char *)log_str);
}

static apr_status_t redirectionio_atoi(const char *line, apr_size_t len) {
    int     value, cutoff, cutlim;

    if (len == 0) {
        return APR_EGENERAL;
    }

    cutoff = INT_MAX / 10;
    cutlim = INT_MAX % 10;

    for (value = 0; len--; line++) {
        if (*line < '0' || *line > '9') {
            return APR_EGENERAL;
        }

        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return APR_EGENERAL;
        }

        value = value * 10 + (*line - '0');
    }

    return value;
}
