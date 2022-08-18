#include <root_certificates.hpp>
#include <io_host.h>
#include <tls_client_host.h>
#include <wss_client_host.h>
#include <wss_client_tunnel.h>

wss_client_host::wss_client_host(const std::shared_ptr<io_host>& host, const wss_client_link& link) noexcept
    : enable_shared_from_this()
    , host_(host)
    , link_(link)
    , server_(*host->def())
    , ssl_((boost::asio::ssl::context::method)tls_client_host::ssl_method(link.tls_.ssl_method)) {
    // This holds the root certificate used for verification.
    load_root_certificates(ssl_);

    // This holds the root certificate used for verification.
    ssl_.set_default_verify_paths();
    ssl_.set_verify_mode(boost::asio::ssl::verify_peer);

    SSL_CTX_set_cipher_list(ssl_.native_handle(), "DEFAULT");
    if (link.tls_.ssl_ciphersuites.size()) {
        // TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
        // TLS_AES_128_GCM_SHA256
        // TLS_AES_256_GCM_SHA384
        // TLS_CHACHA20_POLY1305_SHA256
        // TLS_AES_128_CCM_SHA256
        // TLS_AES_128_CCM_8_SHA256
        SSL_CTX_set_ciphersuites(ssl_.native_handle(), link.tls_.ssl_ciphersuites.data());
    }
    SSL_CTX_set_ecdh_auto(ssl_.native_handle(), 1);
}

wss_client_host::~wss_client_host() noexcept {
    close();
}

bool wss_client_host::run() noexcept {
    try {
        if (tls_client_host::open_socket(server_, link_.tls_.local_host)) {
            return false;
        }

        boost::system::error_code ec_;
        server_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);

        server_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        server_.bind(io_host::endpoint(link_.tls_.local_host, link_.tls_.local_port));
        server_.listen(TCP_LISTEN_BACKLOG);
        tls_client_host::setsockopt(server_);

        if (link_.tls_.remote_nagle) {
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

void wss_client_host::close() noexcept {
    if (server_.is_open()) {
        boost::system::error_code ec;
        try {
            server_.close(ec);
        }
        catch (std::exception&) {}
    }
}

bool wss_client_host::accept_socket() noexcept {
    if (!server_.is_open()) {
        return false;
    }
    std::shared_ptr<boost::asio::io_context> context = host_->get();
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
    std::shared_ptr<wss_client_host> self = shared_from_this();
    server_.async_accept(*socket.get(), [self, this, socket, context](boost::system::error_code ec) noexcept {
        if (ec) {
            tls_client_host::close_socket(*socket.get());
        }
        else {
            std::shared_ptr<wss_client_tunnel> connection_ = make_shared_object<wss_client_tunnel>(self, context, socket);
            if (!connection_->run()) {
                connection_->close();
            }
        }
        accept_socket();
    });
    return true;
}