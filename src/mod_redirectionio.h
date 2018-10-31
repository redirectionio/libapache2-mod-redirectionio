#ifndef mod_redirectionio_h
#define mod_redirectionio_h

#include "apr_network_io.h"

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
