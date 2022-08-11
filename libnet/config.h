#pragma once

#include <stdio.h>
#include <limits.h>

static const int   TCP_BUFFER_SIZE      = 65536;
static const int   TCP_LISTEN_BACKLOG   = 32767; // 511 is nginx

typedef struct {
    typedef enum {
        tlsv13,
        tlsv12,
        tlsv11,
        tls,
        sslv23,
        sslv3,
        sslv2,
        ssl,
    } SSL_METHOD;
    bool                                local_nagle;
    __in_addr__                         local_host;
    int                                 local_port;
    bool                                remote_nagle;
    __in_addr__                         remote_host;
    int                                 remote_port;
    std::string                         host_sni;
    SSL_METHOD                          ssl_method;
    std::string                         ssl_ciphersuites;
} tls_client_link;

typedef struct {
    bool                                local_nagle;
    __in_addr__                         local_host;
    int                                 local_port;
    bool                                remote_nagle;
    __in_addr__                         remote_host;
    int                                 remote_port;
    std::string                         path_;
} ws_link;

typedef struct {
    bool                                local_nagle;
    __in_addr__                         local_host;
    int                                 local_port;
    bool                                remote_nagle;
    __in_addr__                         remote_host;
    int                                 remote_port;
    std::string                         path_;
    std::string                         host_sni;
} ws_client_link;

typedef struct {
    tls_client_link                     tls_;
    std::string                         path_;
} wss_client_link;

typedef struct {
    typedef enum {
        tlsv13,
        tlsv12,
        tlsv11,
        tls,
        sslv23,
        sslv3,
        sslv2,
        ssl,
    } SSL_METHOD;
    bool                                local_nagle;
    __in_addr__                         local_host;
    int                                 local_port;
    bool                                remote_nagle;
    __in_addr__                         remote_host;
    int                                 remote_port;
    std::string                         host_sni;
    std::string                         path_;
    std::string                         ssl_cert_file;
    std::string                         ssl_private_cert;
    std::string                         ssl_verity_pass;
    SSL_METHOD                          ssl_method;
    std::string                         ssl_ciphersuites;
} wss_link;

typedef struct {
    bool                                local_nagle;
    __in_addr__                         local_host;
    int                                 local_port;
    bool                                remote_nagle;
    __in_addr__                         remote_host;
    int                                 remote_port;
} tcp_forward_link;