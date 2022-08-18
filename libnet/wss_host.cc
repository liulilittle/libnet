#include <io_host.h>
#include <tls_client_host.h>
#include <wss_host.h>
#include <wss_tunnel.h>

wss_host::wss_host(const std::shared_ptr<io_host>& host, const wss_link& link) noexcept
    : enable_shared_from_this()
    , host_(host)
    , link_(link)
    , server_(*host->def())
    , ssl_((boost::asio::ssl::context::method)ssl_method(link.ssl_method)) {
    boost::system::error_code ec;
    ssl_.use_certificate_chain_file(link.ssl_cert_file, ec);
    ssl_.use_certificate_file(link.ssl_cert_file, boost::asio::ssl::context::file_format::pem, ec);
    ssl_.use_private_key_file(link.ssl_private_cert, boost::asio::ssl::context::file_format::pem, ec);
    
    // This function is used to specify a callback function to obtain password information about an encrypted key in PEM format.
    ssl_.set_password_callback([link](
        std::size_t max_length, // The maximum size for a password.
        boost::asio::ssl::context_base::password_purpose purpose) noexcept -> std::string { // Whether password is for reading or writing.
        return link.ssl_verity_pass;
    }, ec);

    // This holds the root certificate used for verification.
    ssl_.set_default_verify_paths();

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

wss_host::~wss_host() noexcept {
    close();
}

int wss_host::ssl_method(int method) noexcept {
    switch (method) {
    case tls_client_link::tlsv13:
        return boost::asio::ssl::context::tlsv13_server;
    case tls_client_link::tlsv12:
        return boost::asio::ssl::context::tlsv12_server;
    case tls_client_link::tlsv11:
        return boost::asio::ssl::context::tlsv11_server;
    case tls_client_link::tls:
        return boost::asio::ssl::context::tls_server;
    case tls_client_link::sslv23:
        return boost::asio::ssl::context::sslv23_server;
    case tls_client_link::sslv3:
        return boost::asio::ssl::context::sslv3_server;
    case tls_client_link::sslv2:
        return boost::asio::ssl::context::sslv2_server;
    default:
        return boost::asio::ssl::context::tlsv12_server;
    };
}

bool wss_host::run() noexcept {
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

        if (link_.remote_nagle) {
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

void wss_host::close() noexcept {
    if (server_.is_open()) {
        boost::system::error_code ec;
        try {
            server_.close(ec);
        }
        catch (std::exception&) {}
    }
}

bool wss_host::accept_socket() noexcept {
    if (!server_.is_open()) {
        return false;
    }
    std::shared_ptr<boost::asio::io_context> context = host_->get();
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
    std::shared_ptr<wss_host> self = shared_from_this();
    server_.async_accept(*socket.get(), [self, this, socket, context](boost::system::error_code ec) noexcept {
        if (ec) {
            tls_client_host::close_socket(*socket.get());
        }
        else {
            std::shared_ptr<wss_tunnel> connection_ = make_shared_object<wss_tunnel>(self, context, socket);
            if (!connection_->run()) {
                connection_->close();
            }
        }
        accept_socket();
    });
    return true;
}