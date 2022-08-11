#include <stdafx.h>
#include <config.h>
#include <libnet.h>
#include <io_host.h>
#include <tls_client_host.h>
#include <tls_client_tunnel.h>
#include <ws_host.h>
#include <ws_tunnel.h>
#include <ws_client_host.h>
#include <ws_client_tunnel.h>
#include <wss_host.h>
#include <wss_tunnel.h>
#include <wss_client_host.h>
#include <wss_client_tunnel.h>
#include <tcp_forward_host.h>
#include <tcp_forward_tunnel.h>

typedef std::shared_ptr<io_host>                                                io_host_ptr;
typedef std::unordered_map<io_host*, io_host_ptr>                               io_host_map;
typedef std::shared_ptr<tls_client_host>                                        tls_client_host_ptr;
typedef std::unordered_map<tls_client_host*, tls_client_host_ptr>               tls_client_host_map;
typedef std::shared_ptr<ws_client_host>                                         ws_client_host_ptr;
typedef std::unordered_map<ws_client_host*, ws_client_host_ptr>                 ws_client_host_map;
typedef std::shared_ptr<ws_host>                                                ws_host_ptr;
typedef std::unordered_map<ws_host*, ws_host_ptr>                               ws_host_map;
typedef std::shared_ptr<wss_client_host>                                        wss_client_host_ptr;
typedef std::unordered_map<wss_client_host*, wss_client_host_ptr>               wss_client_host_map;
typedef std::shared_ptr<wss_host>                                               wss_host_ptr;
typedef std::unordered_map<wss_host*, wss_host_ptr>                             wss_host_map;
typedef std::shared_ptr<tcp_forward_host>                                       tcp_forward_host_ptr;
typedef std::unordered_map<tcp_forward_host*, tcp_forward_host_ptr>             tcp_forward_host_map;
typedef std::mutex                                                              lock;
typedef std::lock_guard<lock>                                                   lock_scope;

static lock                                                                     io_host_lock_;
static io_host_map                                                              io_host_map_;
static lock                                                                     tls_client_host_lock_;
static tls_client_host_map                                                      tls_client_host_map_;
static lock                                                                     ws_client_host_lock_;
static ws_client_host_map                                                       ws_client_host_map_;
static lock                                                                     ws_host_lock_;
static ws_host_map                                                              ws_host_map_;
static lock                                                                     wss_client_host_lock_;
static wss_client_host_map                                                      wss_client_host_map_;
static lock                                                                     wss_host_lock_;
static wss_host_map                                                             wss_host_map_;
static lock                                                                     tcp_forward_host_lock_;
static tcp_forward_host_map                                                     tcp_forward_host_map_;

int
libnet_get_cpu_platform(void) {
#ifdef __i386__
    return 1;
#elif __x86_64__
    return 2;
#elif __arm__
    return 3;
#elif __ARM_ARCH_5T__
    return 3;
#elif __ARM_ARCH_7A__
    return 3;
#elif __aarch64__
    return 4;
#elif __powerpc64__
    return 4;
#else
    return sizeof(void*) == 8 ? 2 : 1;
#endif
}

const char*
libnet_get_default_cipher_suites() {
    int cpu_platfrom = libnet_get_cpu_platform();
    if (cpu_platfrom == 3) {
        return "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
    }
    return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
}

void
libnet_process_max_priority(void) {
    io_host::process_max_priority();
}

void 
libnet_thread_max_priority(void) {
    io_host::thread_max_priority();
}

static std::shared_ptr<io_host>
libnet_get_io_host(void* handle_) {
    lock_scope scope_(io_host_lock_);
    io_host_map::iterator tail_ = io_host_map_.find((io_host*)handle_);
    io_host_map::iterator endl_ = io_host_map_.end();
    if (tail_ == endl_) {
        return NULL;
    }
    return tail_->second;
}

bool 
libnet_io_protect(void* io_host_, libnet_io_protect_fn protect) {
    std::shared_ptr<io_host> host_ = libnet_get_io_host(io_host_);
    if (!host_) {
        return false;
    }
    host_->protect_ = protect;
    return true;
}

void*
libnet_new_io_host(int concurrent_) {
    std::shared_ptr<io_host> host_;
    do {
        lock_scope scope_(io_host_lock_);
        if (concurrent_ < 0) {
            concurrent_ = 0;
        }
        host_ = make_shared_object<io_host>(concurrent_);
        io_host_map_.insert(std::make_pair(host_.get(), host_));
    } while (0);
    if (host_) {
        host_->run();
    }
    return (void*)host_.get();
}

bool
libnet_release_io_host(void* handle_) {
    std::shared_ptr<io_host> host_;
    do {
        lock_scope scope_(io_host_lock_);
        io_host_map::iterator tail_ = io_host_map_.find((io_host*)handle_);
        io_host_map::iterator endl_ = io_host_map_.end();
        if (tail_ == endl_) {
            return false;
        }

        host_ = std::move(tail_->second);
        io_host_map_.erase(tail_);
    } while (0);
    if (!host_) {
        return false;
    }
    host_->abort();
    return true;
}

void*
libnet_new_tls_c_host(void* io_host_, TLS_CLIENT_LINK* tls_link_) {
    std::shared_ptr<io_host> host_ = libnet_get_io_host(io_host_);
    if (!host_ || !tls_link_) {
        return NULL;
    }
    if (tls_link_->local_port <= 0 || tls_link_->local_port > UINT16_MAX) {
        return NULL;
    }
    if (tls_link_->remote_port <= 0 || tls_link_->remote_port > UINT16_MAX) {
        return NULL;
    }
    std::shared_ptr<tls_client_host> server_;
    tls_client_link link_;
    link_.local_nagle = tls_link_->local_nagle != 0;
    link_.local_host = tls_link_->local_host;
    link_.local_port = tls_link_->local_port;
    link_.remote_nagle = tls_link_->remote_nagle != 0;
    link_.remote_host = tls_link_->remote_host;
    link_.remote_port = tls_link_->remote_port;
    link_.ssl_method = (tls_client_link::SSL_METHOD)tls_link_->ssl_method;
    if (tls_link_->host_sni) {
        link_.host_sni = tls_link_->host_sni;
    }
    if (tls_link_->ssl_ciphersuites) {
        link_.ssl_ciphersuites = tls_link_->ssl_ciphersuites;
    }
    do {
        lock_scope scope_(tls_client_host_lock_);
        server_ = make_shared_object<tls_client_host>(host_, link_);
        if (!server_->run()) {
            return NULL;
        }
        tls_client_host_map_.insert(std::make_pair(server_.get(), server_));
    } while (0);
    return (void*)server_.get();
}

bool
libnet_release_tls_c_host(void* handle_) {
    std::shared_ptr<tls_client_host> host_;
    do {
        lock_scope scope_(tls_client_host_lock_);
        tls_client_host_map::iterator tail_ = tls_client_host_map_.find((tls_client_host*)handle_);
        tls_client_host_map::iterator endl_ = tls_client_host_map_.end();
        if (tail_ == endl_) {
            return false;
        }

        host_ = std::move(tail_->second);
        tls_client_host_map_.erase(tail_);
    } while (0);
    if (!host_) {
        return false;
    }
    host_->abort();
    return true;
}

void*
libnet_new_ws_s_host(void* io_host_, WS_LINK* ws_link_) {
    std::shared_ptr<io_host> host_ = libnet_get_io_host(io_host_);
    if (!host_ || !ws_link_) {
        return NULL;
    }
    if (ws_link_->local_port <= 0 || ws_link_->local_port > UINT16_MAX) {
        return NULL;
    }
    if (ws_link_->remote_port <= 0 || ws_link_->remote_port > UINT16_MAX) {
        return NULL;
    }
    std::shared_ptr<ws_host> server_;
    ws_link link_;
    link_.local_nagle = ws_link_->local_nagle != 0;
    link_.local_host = ws_link_->local_host;
    link_.local_port = ws_link_->local_port;
    link_.remote_nagle = ws_link_->remote_nagle != 0;
    link_.remote_host = ws_link_->remote_host;
    link_.remote_port = ws_link_->remote_port;
    if (ws_link_->path_) {
        link_.path_ = ws_link_->path_;
    }
    link_.path_ = LTrim(RTrim(link_.path_));
    if (link_.path_.empty()) {
        link_.path_ = "/";
    }
    do {
        lock_scope scope_(ws_host_lock_);
        server_ = make_shared_object<ws_host>(host_, link_);
        if (!server_->run()) {
            return NULL;
        }
        ws_host_map_.insert(std::make_pair(server_.get(), server_));
    } while (0);
    return (void*)server_.get();
}

bool
libnet_release_ws_s_host(void* handle_) {
    std::shared_ptr<ws_host> host_;
    do {
        lock_scope scope_(ws_host_lock_);
        ws_host_map::iterator tail_ = ws_host_map_.find((ws_host*)handle_);
        ws_host_map::iterator endl_ = ws_host_map_.end();
        if (tail_ == endl_) {
            return false;
        }

        host_ = std::move(tail_->second);
        ws_host_map_.erase(tail_);
    } while (0);
    if (!host_) {
        return false;
    }
    host_->abort();
    return true;
}

void*
libnet_new_ws_c_host(void* io_host_, WS_CLIENT_LINK* ws_link_) {
    std::shared_ptr<io_host> host_ = libnet_get_io_host(io_host_);
    if (!host_ || !ws_link_) {
        return NULL;
    }
    if (ws_link_->local_port <= 0 || ws_link_->local_port > UINT16_MAX) {
        return NULL;
    }
    if (ws_link_->remote_port <= 0 || ws_link_->remote_port > UINT16_MAX) {
        return NULL;
    }
    std::shared_ptr<ws_client_host> server_;
    ws_client_link link_;
    link_.local_nagle = ws_link_->local_nagle != 0;
    link_.local_host = ws_link_->local_host;
    link_.local_port = ws_link_->local_port;
    link_.remote_nagle = ws_link_->remote_nagle != 0;
    link_.remote_host = ws_link_->remote_host;
    link_.remote_port = ws_link_->remote_port;
    if (ws_link_->path_) {
        link_.path_ = ws_link_->path_;
    }
    if (ws_link_->host_sni) {
        link_.host_sni = ws_link_->host_sni;
    }
    link_.path_ = LTrim(RTrim(link_.path_));
    if (link_.path_.empty()) {
        link_.path_ = "/";
    }
    do {
        lock_scope scope_(ws_client_host_lock_);
        server_ = make_shared_object<ws_client_host>(host_, link_);
        if (!server_->run()) {
            return NULL;
        }
        ws_client_host_map_.insert(std::make_pair(server_.get(), server_));
    } while (0);
    return (void*)server_.get();
}

bool
libnet_release_ws_c_host(void* handle_) {
    std::shared_ptr<ws_client_host> host_;
    do {
        lock_scope scope_(ws_client_host_lock_);
        ws_client_host_map::iterator tail_ = ws_client_host_map_.find((ws_client_host*)handle_);
        ws_client_host_map::iterator endl_ = ws_client_host_map_.end();
        if (tail_ == endl_) {
            return false;
        }

        host_ = std::move(tail_->second);
        ws_client_host_map_.erase(tail_);
    } while (0);
    if (!host_) {
        return false;
    }
    host_->abort();
    return true;
}

void*
libnet_new_wss_c_host(void* io_host_, WSS_CLIENT_LINK* wss_link_) {
    std::shared_ptr<io_host> host_ = libnet_get_io_host(io_host_);
    if (!host_ || !wss_link_) {
        return NULL;
    }
    if (wss_link_->tls_.local_port <= 0 || wss_link_->tls_.local_port > UINT16_MAX) {
        return NULL;
    }
    if (wss_link_->tls_.remote_port <= 0 || wss_link_->tls_.remote_port > UINT16_MAX) {
        return NULL;
    }
    std::shared_ptr<wss_client_host> server_;
    wss_client_link link_;
    link_.tls_.local_nagle = wss_link_->tls_.local_nagle != 0;
    link_.tls_.local_host = wss_link_->tls_.local_host;
    link_.tls_.local_port = wss_link_->tls_.local_port;
    link_.tls_.remote_nagle = wss_link_->tls_.remote_nagle != 0;
    link_.tls_.remote_host = wss_link_->tls_.remote_host;
    link_.tls_.remote_port = wss_link_->tls_.remote_port;
    link_.tls_.ssl_method = (tls_client_link::SSL_METHOD)wss_link_->tls_.ssl_method;
    if (wss_link_->tls_.host_sni) {
        link_.tls_.host_sni = wss_link_->tls_.host_sni;
    }
    if (wss_link_->tls_.ssl_ciphersuites) {
        link_.tls_.ssl_ciphersuites = wss_link_->tls_.ssl_ciphersuites;
    }
    if (wss_link_->path_) {
        link_.path_ = wss_link_->path_;
    }
    link_.path_ = LTrim(RTrim(link_.path_));
    if (link_.path_.empty()) {
        link_.path_ = "/";
    }
    do {
        lock_scope scope_(wss_client_host_lock_);
        server_ = make_shared_object<wss_client_host>(host_, link_);
        if (!server_->run()) {
            return NULL;
        }
        wss_client_host_map_.insert(std::make_pair(server_.get(), server_));
    } while (0);
    return (void*)server_.get();
}

bool
libnet_release_wss_c_host(void* handle_) {
    std::shared_ptr<wss_client_host> host_;
    do {
        lock_scope scope_(wss_client_host_lock_);
        wss_client_host_map::iterator tail_ = wss_client_host_map_.find((wss_client_host*)handle_);
        wss_client_host_map::iterator endl_ = wss_client_host_map_.end();
        if (tail_ == endl_) {
            return false;
        }

        host_ = std::move(tail_->second);
        wss_client_host_map_.erase(tail_);
    } while (0);
    if (!host_) {
        return false;
    }
    host_->abort();
    return true;
}

void*
libnet_new_wss_s_host(void* io_host_, WSS_LINK* wss_link_) {
    std::shared_ptr<io_host> host_ = libnet_get_io_host(io_host_);
    if (!host_ || !wss_link_) {
        return NULL;
    }
    if (wss_link_->local_port <= 0 || wss_link_->local_port > UINT16_MAX) {
        return NULL;
    }
    if (wss_link_->remote_port <= 0 || wss_link_->remote_port > UINT16_MAX) {
        return NULL;
    }
    std::shared_ptr<wss_host> server_;
    wss_link link_;
    if (wss_link_->ssl_cert_file) {
        link_.ssl_cert_file = wss_link_->ssl_cert_file;
    }
    if (wss_link_->ssl_private_cert) {
        link_.ssl_private_cert = wss_link_->ssl_private_cert;
    }
    if (link_.ssl_cert_file.empty() || link_.ssl_private_cert.empty()) {
        return NULL;
    }
    if (wss_link_->host_sni) {
        link_.host_sni = wss_link_->host_sni;
    }
    if (wss_link_->ssl_ciphersuites) {
        link_.ssl_ciphersuites = wss_link_->ssl_ciphersuites;
    }
    if (wss_link_->path_) {
        link_.path_ = wss_link_->path_;
    }
    if (wss_link_->ssl_verity_pass) {
        link_.ssl_verity_pass = wss_link_->ssl_verity_pass;
    }
    link_.path_ = LTrim(RTrim(link_.path_));
    if (link_.path_.empty()) {
        link_.path_ = "/";
    }
    link_.local_nagle = wss_link_->local_nagle != 0;
    link_.local_host = wss_link_->local_host;
    link_.local_port = wss_link_->local_port;
    link_.remote_nagle = wss_link_->remote_nagle != 0;
    link_.remote_host = wss_link_->remote_host;
    link_.remote_port = wss_link_->remote_port;
    link_.ssl_method = (wss_link::SSL_METHOD)wss_link_->ssl_method;
    do {
        lock_scope scope_(wss_host_lock_);
        server_ = make_shared_object<wss_host>(host_, link_);
        if (!server_->run()) {
            return NULL;
        }
        wss_host_map_.insert(std::make_pair(server_.get(), server_));
    } while (0);
    return (void*)server_.get();
}

bool
libnet_release_wss_s_host(void* handle_) {
    std::shared_ptr<wss_host> host_;
    do {
        lock_scope scope_(wss_host_lock_);
        wss_host_map::iterator tail_ = wss_host_map_.find((wss_host*)handle_);
        wss_host_map::iterator endl_ = wss_host_map_.end();
        if (tail_ == endl_) {
            return false;
        }

        host_ = std::move(tail_->second);
        wss_host_map_.erase(tail_);
    } while (0);
    if (!host_) {
        return false;
    }
    host_->abort();
    return true;
}

void*
libnet_new_tcp_forward_host(void* io_host_, TCP_FORWARD_LINK* link__) {
    std::shared_ptr<io_host> host_ = libnet_get_io_host(io_host_);
    if (!host_ || !link__) {
        return NULL;
    }
    if (link__->local_port <= 0 || link__->local_port > UINT16_MAX) {
        return NULL;
    }
    if (link__->remote_port <= 0 || link__->remote_port > UINT16_MAX) {
        return NULL;
    }
    std::shared_ptr<tcp_forward_host> server_;
    tcp_forward_link link_;
    link_.local_nagle = link__->local_nagle != 0;
    link_.local_host = link__->local_host;
    link_.local_port = link__->local_port;
    link_.remote_nagle = link__->remote_nagle != 0;
    link_.remote_host = link__->remote_host;
    link_.remote_port = link__->remote_port;
    do {
        lock_scope scope_(tcp_forward_host_lock_);
        server_ = make_shared_object<tcp_forward_host>(host_, link_);
        if (!server_->run()) {
            return NULL;
        }
        tcp_forward_host_map_.insert(std::make_pair(server_.get(), server_));
    } while (0);
    return (void*)server_.get();
}

bool
libnet_release_tcp_forward_host(void* handle_) {
    std::shared_ptr<tcp_forward_host> host_;
    do {
        lock_scope scope_(tcp_forward_host_lock_);
        tcp_forward_host_map::iterator tail_ = tcp_forward_host_map_.find((tcp_forward_host*)handle_);
        tcp_forward_host_map::iterator endl_ = tcp_forward_host_map_.end();
        if (tail_ == endl_) {
            return false;
        }

        host_ = std::move(tail_->second);
        tcp_forward_host_map_.erase(tail_);
    } while (0);
    if (!host_) {
        return false;
    }
    host_->abort();
    return true;
}