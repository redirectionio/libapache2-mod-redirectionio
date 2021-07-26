#ifndef mod_redirectionio_h
#define mod_redirectionio_h

#include "apr_network_io.h"
#include "apr_reslist.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_network_io.h"
#include "apr_strings.h"
#include "apr_uri.h"
#include "redirectionio.h"

#ifndef APR_UNIX
#if defined (AF_UNIX)
#define APR_UNIX    AF_UNIX
#elif defined(AF_LOCAL)
#define APR_UNIX    AF_LOCAL
#else
#error "Neither AF_UNIX nor AF_LOCAL is defined"
#endif
#endif

#define UNIX 0
#define TCP 1

#ifndef PROXY_VERSION
#define PROXY_VERSION libapache2-mod-redirectionio:dev
#endif

#define STRINGIZE(x) #x
#define PROXY_VERSION_STR(x) STRINGIZE(x)

#define RIO_TIMEOUT 100 // Timeout in microseconds
#define RIO_RECONNECT_INTERVAL 0
#define RIO_MIN_CONNECTIONS 1
#define RIO_KEEP_CONNECTIONS 10
#define RIO_MAX_CONNECTIONS 100
#define RIO_SEND_BUFFER 1048576

typedef struct {
    char*                   pass;
    int                     port;
    int                     protocol;
    int                     min_conns;
    int                     max_conns;
    int                     keep_conns;
    apr_interval_time_t     timeout;
    int                     pass_set;
} redirectionio_server;

typedef struct {
    const char*                         project_key;
    const char*                         scheme;
    redirectionio_server                server;
    int                                 enable;
    int                                 enable_logs;
    int                                 show_rule_ids;
    apr_reslist_t                       *connection_pool;
    apr_pool_t                          *pool;
    apr_table_t                         *headers_set;
    struct REDIRECTIONIO_TrustedProxies *trusted_proxies;
} redirectionio_config;

typedef struct {
	apr_socket_t    *rio_sock;
	apr_sockaddr_t  *rio_addr;
} redirectionio_connection;

typedef struct {
    struct REDIRECTIONIO_Request            *request;
    struct REDIRECTIONIO_Action             *action;
    struct REDIRECTIONIO_HeaderMap          *response_headers;
    struct REDIRECTIONIO_FilterBodyAction   *body_filter;
} redirectionio_context;

module AP_MODULE_DECLARE_DATA redirectionio_module;

#endif
