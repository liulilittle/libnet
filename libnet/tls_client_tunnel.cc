#include <io_host.h>
#include <tls_client_host.h>
#include <tls_client_tunnel.h>

bool tls_client_tunnel::run() {
    std::shared_ptr<tls_client_tunnel> self = shared_from_this();
    try {
        // Make the connection on the IP address we get from a lookup.
        tls_client_link& link_ = host_->link_;
        auto& socket_ = remote_socket_.lowest_layer();

        boost::system::error_code ec = tls_client_host::open_socket(socket_, link_.remote_host);
        if (ec) {
            return false;
        }

        socket_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec);
        if (link_.remote_nagle) {
            socket_.set_option(boost::asio::ip::tcp::no_delay(false), ec);
        }
        else {
            socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        }

        tls_client_host::bind_socket(socket_, link_.remote_host);
        tls_client_host::setsockopt(socket_);
        
        boost::asio::ip::tcp::endpoint localEP = local_socket_->remote_endpoint(ec);
        boost::asio::ip::tcp::endpoint natEP = socket_.local_endpoint(ec);

        std::shared_ptr<io_host>& host = host_->host_;
        if (host->protect_) {
            if (!host->protect(
                socket_.native_handle(),
                natEP,
                localEP,
                link_.remote_host,
                link_.remote_port)) {
                return false;
            }
        }

        socket_.async_connect(io_host::endpoint(link_.remote_host, link_.remote_port),
            [self, this](const boost::system::error_code& ec) {
                if (ec) {
                    abort();
                    return;
                }

                // Perform the SSL handshake.
                remote_socket_.async_handshake(boost::asio::ssl::stream_base::client, [self, this](const boost::system::error_code& ec) {
                    if (ec) {
                        abort();
                        return;
                    }

                    local_to_remote();
                    remote_to_local();
                });
            });
        return true;
    }
    catch (std::exception&) {
        return false;
    }
}

void tls_client_tunnel::abort() {
    if (!fin_.exchange(true)) {
        std::shared_ptr<tls_client_tunnel> self = shared_from_this();
        remote_socket_.async_shutdown(
            [self, this](const boost::system::error_code& ec_) {
                finalize();
            });
        tls_client_host::close_socket(*local_socket_.get());
    }
}

void tls_client_tunnel::finalize() {
    auto& remote_socket = remote_socket_.lowest_layer();
    if (remote_socket.is_open()) {
        boost::system::error_code ec_;
        try {
            remote_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec_);
        }
        catch (std::exception&) {}
        try {
            remote_socket.close(ec_);
        }
        catch (std::exception&) {}
    }
    tls_client_host::close_socket(*local_socket_.get());
}

tls_client_tunnel::~tls_client_tunnel() {
    finalize();
}

tls_client_tunnel::tls_client_tunnel(
    const std::shared_ptr<tls_client_host>& host,
    const std::shared_ptr<boost::asio::io_context>& context,
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket)
    : enable_shared_from_this()
    , fin_(false)
    , context_(context)
    , host_(host)
    , local_socket_(socket)
    , remote_socket_(*context, host->ssl_) {
    tls_client_host::setsockopt(*socket);

    boost::system::error_code ec;
    if (host->link_.local_nagle) {
        socket->set_option(boost::asio::ip::tcp::no_delay(false), ec);
    }
    else {
        socket->set_option(boost::asio::ip::tcp::no_delay(true), ec);
    }

    // Set SNI Hostname(many hosts need this to handshake successfully).
    const std::string& host_name = host->link_.host_sni;
    if (host_name.size()) {
        if (!SSL_set_tlsext_host_name(remote_socket_.native_handle(), host_name.data())) {
            ec = { static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
            throw boost::system::system_error{ ec };
        }
    }
}

bool tls_client_tunnel::remote_to_local() {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<tls_client_tunnel> self = shared_from_this();
    remote_socket_.async_read_some(boost::asio::buffer(remote_socket_buf_, TCP_BUFFER_SIZE),
        [self, this](const boost::system::error_code& ec, uint32_t sz) {
            int by = std::max<int>(-1, ec ? -1 : sz);
            if (by <= 0) {
                abort();
                return;
            }

            boost::asio::async_write(*local_socket_.get(), boost::asio::buffer(remote_socket_buf_, by),
                [self, this](const boost::system::error_code& ec, uint32_t sz) {
                    if (ec) {
                        abort();
                        return;
                    }
                    remote_to_local();
                });
        });
    return true;
}

bool tls_client_tunnel::local_to_remote() {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<tls_client_tunnel> self = shared_from_this();
    local_socket_->async_receive(boost::asio::buffer(local_socket_buf_, TCP_BUFFER_SIZE),
        [self, this](const boost::system::error_code& ec, uint32_t sz) {
            int by = std::max<int>(-1, ec ? -1 : sz);
            if (by <= 0) {
                abort();
                return;
            }

            boost::asio::async_write(remote_socket_, boost::asio::buffer(local_socket_buf_, by),
                [self, this](const boost::system::error_code& ec, uint32_t sz) {
                    if (ec) {
                        abort();
                        return;
                    }
                    local_to_remote();
                });
        });
    return true;
}