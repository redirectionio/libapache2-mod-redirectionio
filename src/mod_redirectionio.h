#ifndef mod_redirectionio_h
#define mod_redirectionio_h

#include "apr_network_io.h"
#include "apr_reslist.h"

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

#define RIO_TIMEOUT 100000 // Timeout in microseconds
#define RIO_RECONNECT_INTERVAL 0
#define RIO_MIN_CONNECTIONS 1
#define RIO_KEEP_CONNECTIONS 10
#define RIO_MAX_CONNECTIONS 100
#define RIO_SEND_BUFFER 1048576

typedef struct {
    const char*     project_key;
    char*           server;
    int             port;
    int             protocol;
    int             enable;
    int             enable_logs;
    int             pass_set;
    apr_reslist_t   *connection_pool;
} redirectionio_config;

typedef struct {
	apr_socket_t    *rio_sock;
	apr_sockaddr_t  *rio_addr;
} redirectionio_connection;

typedef struct {
    char                        *matched_rule_id;
    char                        *target;
    int                         status;
    int                         match_on_response_status;
    int                         is_redirected;
    int                         should_filter_headers;
    int                         should_filter_body;
    redirectionio_connection    *body_filter_conn;
} redirectionio_context;

#endif
