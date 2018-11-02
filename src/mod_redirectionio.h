#ifndef mod_redirectionio_h
#define mod_redirectionio_h

#include "apr_network_io.h"

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

#define SEND_BUFFER 1048576

typedef struct {
    const char*     project_key;
    char*           server;
    int             port;
    int             protocol;
    int             enable;
    int             enable_logs;
} redirectionio_config;

typedef struct {
	apr_socket_t    *rio_sock;
	apr_sockaddr_t  *rio_addr;
} redirectionio_connection;

typedef struct {
    redirectionio_connection    *conn;
    char                        *matched_rule_id;
    char                        *target;
    int                         status;
} redirectionio_context;

#endif
