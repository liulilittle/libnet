#include <root_certificates.hpp>
#include <io_host.h>
#include <tls_client_host.h>
#include <tls_client_tunnel.h>

bool tls_client_host::accept_socket() noexcept {
    if (!server_.is_open()) {
        return false;
    }
    std::shared_ptr< boost::asio::io_context> context = host_->get();
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
    std::shared_ptr<tls_client_host> self = shared_from_this();
    server_.async_accept(*socket.get(), [self, this, socket, context](boost::system::error_code ec) noexcept {
        if (ec) {
            close_socket(*socket.get());
        }
        else {
            std::shared_ptr<tls_client_tunnel> connection_ = make_shared_object<tls_client_tunnel>(self, context, socket);
            if (!connection_->run()) {
                connection_->close();
            }
        }
        accept_socket();
    });
    return true;
}

void tls_client_host::close_socket(boost::asio::ip::tcp::socket& s) noexcept {
    if (s.is_open()) {
        boost::system::error_code ec;
        try {
            s.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        }
        catch (std::exception&) {}
        try {
            s.close(ec);
        }
        catch (std::exception&) {}
    }
}

void tls_client_host::setsockopt(int sockfd, bool v4_or_v6) noexcept {
    if (sockfd != -1) {
        uint8_t tos = 0x68;
        if (v4_or_v6) {
            ::setsockopt(sockfd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos));

#ifdef _WIN32
            int dont_frag = 0;
            ::setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif IP_MTU_DISCOVER
            int dont_frag = IP_PMTUDISC_WANT;
            ::setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
        }
        else {
            ::setsockopt(sockfd, SOL_IPV6, IP_TOS, (char*)&tos, sizeof(tos));

#ifdef _WIN32
            int dont_frag = 0;
            ::setsockopt(sockfd, IPPROTO_IPV6, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif IPV6_MTU_DISCOVER
            int dont_frag = IPV6_PMTUDISC_WANT;
            ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
        }
#ifdef SO_NOSIGPIPE
        int no_sigpipe = 1;
        ::setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
    }
}

bool tls_client_host::run() noexcept {
    try {
        if (tls_client_host::open_socket(server_, link_.local_host)) {
            return false;
        }

        boost::system::error_code ec_;
        server_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);

        server_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        server_.bind(io_host::endpoint(link_.local_host, link_.local_port));
        server_.listen(TCP_LISTEN_BACKLOG);
        tls_client_host::setsockopt(server_);

        if (link_.local_nagle) {
            server_.set_option(boost::asio::ip::tcp::no_delay(false));
        }
        else {
            server_.set_option(boost::asio::ip::tcp::no_delay(true));
        }

        accept_socket();
        return true;
    }
    catch (std::exception&) {
        return false;
    }
}

int tls_client_host::ssl_method(int method) noexcept {
    switch (method) {
    case tls_client_link::tlsv13:
        return boost::asio::ssl::context::tlsv13_client;
    case tls_client_link::tlsv12:
        return boost::asio::ssl::context::tlsv12_client;
    case tls_client_link::tlsv11:
        return boost::asio::ssl::context::tlsv11_client;
    case tls_client_link::tls:
        return boost::asio::ssl::context::tls_client;
    case tls_client_link::sslv23:
        return boost::asio::ssl::context::sslv23_client;
    case tls_client_link::sslv3:
        return boost::asio::ssl::context::sslv3_client;
    case tls_client_link::sslv2:
        return boost::asio::ssl::context::sslv2_client;
    default:
        return boost::asio::ssl::context::tlsv12_client;
    };
}

tls_client_host::tls_client_host(const std::shared_ptr<io_host>& host, const tls_client_link& link) noexcept
    : enable_shared_from_this()
    , host_(host)
    , link_(link)
    , server_(*host->def())
    , ssl_((boost::asio::ssl::context::method)ssl_method(link.ssl_method)) {
    // This holds the root certificate used for verification.
    load_root_certificates(ssl_);

    // This holds the root certificate used for verification.
    ssl_.set_default_verify_paths();
    ssl_.set_verify_mode(boost::asio::ssl::verify_peer);

    SSL_CTX_set_cipher_list(ssl_.native_handle(), "DEFAULT");
    if (link.ssl_ciphersuites.size()) {
        // TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
        // TLS_AES_128_GCM_SHA256
        // TLS_AES_256_GCM_SHA384
        // TLS_CHACHA20_POLY1305_SHA256
        // TLS_AES_128_CCM_SHA256
        // TLS_AES_128_CCM_8_SHA256
        SSL_CTX_set_ciphersuites(ssl_.native_handle(), link.ssl_ciphersuites.data());
    }
    SSL_CTX_set_ecdh_auto(ssl_.native_handle(), 1);
}

tls_client_host::~tls_client_host() noexcept {
    close();
}

void tls_client_host::close() noexcept {
    if (server_.is_open()) {
        boost::system::error_code ec;
        try {
            server_.close(ec);
        }
        catch (std::exception&) {}
    }
}