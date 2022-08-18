#ifndef _LIBNET_H
#define _LIBNET_H

#include <stdint.h>
#include <common.h>

#ifndef LIBNET_API
#ifdef __cplusplus 
#ifdef _WIN32
#define LIBNET_API extern "C" __declspec(dllexport)
#else
#define LIBNET_API extern "C" __attribute__((visibility("default")))
#endif
#else
#define LIBNET_API
#endif
#endif
typedef bool(*libnet_io_protect_fn)(
    void* iohost,
    int                             sockfd,
    __in_addr__* natAddr,           
    int                             natPort,
    __in_addr__* srcAddr,           
    int                             srcPort,
    __in_addr__* dstAddr,           
    int                             dstPort);

#ifdef __cplusplus
extern "C" {
#endif
    LIBNET_API int                  libnet_get_cpu_platform(void) noexcept;
    LIBNET_API const char*          libnet_get_default_cipher_suites() noexcept;
    LIBNET_API bool                 libnet_io_protect(void* io_host_, libnet_io_protect_fn protect) noexcept;
    LIBNET_API void*                libnet_new_io_host(int concurrent_) noexcept;
    LIBNET_API bool                 libnet_release_io_host(void* handle_) noexcept;
    LIBNET_API void                 libnet_process_max_priority(void) noexcept;
    LIBNET_API void                 libnet_thread_max_priority(void) noexcept;
#pragma pack(push,1)
    typedef struct {
        int                         local_nagle;
        __in_addr__                 local_host;
        int                         local_port;
        int                         remote_nagle;
        __in_addr__                 remote_host;
        int                         remote_port;
        const char*                 host_sni;
        int                         ssl_method;
        const char*                 ssl_ciphersuites;
    } TLS_CLIENT_LINK;
#pragma pack(pop)
    LIBNET_API void*                libnet_new_tls_c_host(void* io_host_, TLS_CLIENT_LINK* tls_link_) noexcept;
    LIBNET_API bool                 libnet_release_tls_c_host(void* handle_) noexcept;
#pragma pack(push,1)
    typedef struct {
        int                         local_nagle;
        __in_addr__                 local_host;
        int                         local_port;
        int                         remote_nagle;
        __in_addr__                 remote_host;
        int                         remote_port;
        const char*                 path_;
    } WS_LINK;
#pragma pack(pop)
    LIBNET_API void*                libnet_new_ws_s_host(void* io_host_, WS_LINK* ws_link_) noexcept;
    LIBNET_API bool                 libnet_release_ws_s_host(void* handle_) noexcept;
#pragma pack(push,1)
    typedef struct {
        int                         local_nagle;
        __in_addr__                 local_host;
        int                         local_port;
        int                         remote_nagle;
        __in_addr__                 remote_host;
        int                         remote_port;
        const char*                 host_sni;
        const char*                 path_;
    } WS_CLIENT_LINK;
#pragma pack(pop)
    LIBNET_API void*                libnet_new_ws_c_host(void* io_host_, WS_CLIENT_LINK* ws_link_) noexcept;
    LIBNET_API bool                 libnet_release_ws_c_host(void* handle_) noexcept;
#pragma pack(push,1)
    typedef struct {
        TLS_CLIENT_LINK             tls_;
        const char*                 path_;
    } WSS_CLIENT_LINK;
#pragma pack(pop)
    LIBNET_API void*                libnet_new_wss_c_host(void* io_host_, WSS_CLIENT_LINK* ws_link_) noexcept;
    LIBNET_API bool                 libnet_release_wss_c_host(void* handle_) noexcept;
#pragma pack(push,1)
    typedef struct {
        int                         local_nagle;
        __in_addr__                 local_host;
        int                         local_port;
        int                         remote_nagle;
        __in_addr__                 remote_host;
        int                         remote_port;
        const char*                 host_sni;
        const char*                 path_;
        const char*                 ssl_cert_file;
        const char*                 ssl_private_cert;
        const char*                 ssl_verity_pass;
        int                         ssl_method;
        const char*                 ssl_ciphersuites;
    } WSS_LINK;
#pragma pack(pop)
    LIBNET_API void*                libnet_new_wss_s_host(void* io_host_, WSS_LINK* ws_link_) noexcept;
    LIBNET_API bool                 libnet_release_wss_s_host(void* handle_) noexcept;
#pragma pack(push,1)
    typedef struct {
        int                         local_nagle;
        __in_addr__                 local_host;
        int                         local_port;
        int                         remote_nagle;
        __in_addr__                 remote_host;
        int                         remote_port;
    } TCP_FORWARD_LINK;
#pragma pack(pop)
    LIBNET_API void*                libnet_new_tcp_forward_host(void* io_host_, TCP_FORWARD_LINK* link__) noexcept;
    LIBNET_API bool                 libnet_release_tcp_forward_host(void* handle_) noexcept;
#ifdef __cplusplus
}
#endif
#endif