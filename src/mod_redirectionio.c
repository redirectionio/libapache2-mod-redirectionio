#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_network_io.h"
#include "apr_strings.h"
#include "apr_uri.h"
#include "mod_redirectionio.h"
#include "redirectionio_protocol.h"

static char errbuf[1024];

static void redirectionio_register_hooks(apr_pool_t *p);

static int redirectionio_redirect_handler(request_rec *r);
static int redirectionio_log_handler(request_rec *r);

static apr_status_t redirectionio_create_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool);

static void *create_redirectionio_dir_conf(apr_pool_t *pool, char *context);
static void *merge_redirectionio_dir_conf(apr_pool_t *pool, void *BASE, void *ADD);

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
    ap_hook_handler(redirectionio_redirect_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_log_transaction(redirectionio_log_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static int redirectionio_redirect_handler(request_rec *r) {
    redirectionio_config *config = (redirectionio_config*) ap_get_module_config(r->per_dir_config, &redirectionio_module);

    if (config->enable != 1) {
        return DECLINED;
    }

    // Create context
    redirectionio_context* context = apr_palloc(r->pool, sizeof(redirectionio_context));

    if (context == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Cannot create redirectionio context");

        return DECLINED;
    }

    ap_set_module_config(r->request_config, &redirectionio_module, context);

    // Create connection
    context->conn = apr_palloc(r->pool, sizeof(redirectionio_connection));

    if (context->conn == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Cannot create redirectionio context");

        return DECLINED;
    }

    if (redirectionio_create_connection(context->conn, config, r->pool) != APR_SUCCESS) {
        return DECLINED;
    }

    // Ask for redirection
    if (redirectionio_protocol_match(context, r, config->project_key) != APR_SUCCESS) {
        return DECLINED;
    }

    // No match
    if (context->status == 0) {
        return DECLINED;
    }

    if (context->status != 410) {
        apr_table_setn(r->headers_out, "Location", context->target);
    }

    r->status = context->status;

    return context->status;
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

    if (context == NULL || context->conn == NULL) {
        return DECLINED;
    }

    if (redirectionio_protocol_log(context, r, config->project_key) != APR_SUCCESS) {
        return DECLINED;
    }

    return OK;
}

static apr_status_t redirectionio_create_connection(redirectionio_connection *conn, redirectionio_config *config, apr_pool_t *pool) {
    apr_status_t    rv;
    apr_int32_t     family = APR_INET;

    if (config->protocol == UNIX) {
        family = APR_UNIX;
    }

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool, "mod_redirectionio: Connecting to server: %s", config->server);
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

//    rv = apr_socket_timeout_set(conn->rio_sock, 0);
//
//    if (rv != APR_SUCCESS) {
//        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "mod_redirectionio: Error setting socket timeout: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
//
//        return rv;
//    }

    return APR_SUCCESS;
}

static void *create_redirectionio_dir_conf(apr_pool_t *pool, char *context) {
    context = context ? context : "(undefined context)";
    redirectionio_config *config = apr_pcalloc(pool, sizeof(redirectionio_config));

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
    redirectionio_config *conf_parent = (redirectionio_config *) parent;
    redirectionio_config *conf_current = (redirectionio_config *) current;
    redirectionio_config *conf = (redirectionio_config *) create_redirectionio_dir_conf(pool, "Merged configuration");

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

    return conf;
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
