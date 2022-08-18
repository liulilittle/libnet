#include <io_host.h>
#include <tls_client_host.h>
#include <ws_host.h>
#include <ws_tunnel.h>
#include <wss_host.h>
#include <wss_tunnel.h>

bool wss_tunnel::run() noexcept {
    std::shared_ptr<wss_tunnel> self = shared_from_this();
    try {
        // Make the connection on the IP address we get from a lookup.
        wss_link& link_ = host_->link_;
        boost::system::error_code ec = tls_client_host::open_socket(remote_socket_, link_.remote_host);
        if (ec) {
            return false;
        }

        remote_socket_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec);
        if (link_.remote_nagle) {
            remote_socket_.set_option(boost::asio::ip::tcp::no_delay(false), ec);
        }
        else {
            remote_socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        }

        tls_client_host::bind_socket(remote_socket_, link_.remote_host);
        tls_client_host::setsockopt(remote_socket_);

        boost::asio::ip::tcp::endpoint localEP = local_socket_.next_layer().next_layer().remote_endpoint(ec);
        boost::asio::ip::tcp::endpoint natEP = remote_socket_.local_endpoint(ec);

        std::shared_ptr<io_host>& host = host_->host_;
        if (host->protect_) {
            if (!host->protect(
                remote_socket_.native_handle(),
                natEP,
                localEP,
                link_.remote_host,
                link_.remote_port)) {
                return false;
            }
        }

        // Perform the Async connect.
        remote_socket_.async_connect(io_host::endpoint(link_.remote_host, link_.remote_port),
            [self, this](const boost::system::error_code& ec) noexcept {
                if (ec) {
                    close();
                    return;
                }
                ack_establish(false);
            });

        // Perform the SSL handshake.
        local_socket_.next_layer().async_handshake(boost::asio::ssl::stream_base::server, [self, this](const boost::system::error_code& ec) noexcept {
            typedef boost::beast::http::request<boost::beast::http::dynamic_body> http_request;

            if (ec) {
                close();
                return;
            }

            // This buffer is used for reading and must be persisted
            std::shared_ptr<boost::beast::flat_buffer> buffer = make_shared_object<boost::beast::flat_buffer>();

            // Declare a container to hold the response
            std::shared_ptr<http_request> req = make_shared_object<http_request>();

            // Receive the HTTP response
            boost::beast::http::async_read(local_socket_.next_layer(), *buffer.get(), *req.get(), [self, this, buffer, req](boost::system::error_code ec, std::size_t sz) noexcept {
                if (ec == boost::beast::http::error::end_of_stream) {
                    ec = boost::beast::websocket::error::closed;
                }

                if (ec) {
                    close();
                    return;
                }

                try {
                    local_socket_.accept(*req.get(), ec);
                }
                catch (std::exception&) {
                    ec = boost::beast::websocket::error::closed;
                }

                if (ec) {
                    close();
                    return;
                }

                wss_link& link_ = host_->link_;
                if (!ws_tunnel::check_path(link_.path_, req->target())) {
                    close();
                    return;
                }
                ack_establish(true);
            });
        });
        return true;
    }
    catch (std::exception&) {
        return false;
    }
}

int wss_tunnel::ack_establish(bool local) noexcept {
    if (local) {
        local_ok_ = true;
    }
    else {
        remote_ok_ = true;
    }

    if (local_ok_ && remote_ok_) {
        local_to_remote();
        remote_to_local();
        return 0;
    }
    return remote_socket_.is_open() ? 1 : -1;
}

void wss_tunnel::close() noexcept {
    if (!fin_.exchange(true)) {
        std::shared_ptr<wss_tunnel> self = shared_from_this();
        local_socket_.async_close(boost::beast::websocket::close_code::normal,
            [self, this](const boost::system::error_code& ec_) noexcept {
                local_socket_.next_layer().async_shutdown(
                    [self, this](const boost::system::error_code& ec_) noexcept {
                        finalize();
                    });
            });
        tls_client_host::close_socket(remote_socket_);
    }
}

void wss_tunnel::finalize() noexcept {
    local_socket_buf_.clear();
    tls_client_host::close_socket(remote_socket_);
    tls_client_host::close_socket(local_socket_.next_layer().next_layer());
}

wss_tunnel::~wss_tunnel() noexcept {
    finalize();
}

wss_tunnel::wss_tunnel(
    const std::shared_ptr<wss_host>&                        host,
    const std::shared_ptr<boost::asio::io_context>&         context,
    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket)
    : enable_shared_from_this()
    , fin_(false)
    , local_ok_(false)
    , remote_ok_(false)
    , context_(context)
    , host_(host)
    , local_socket_(std::move(*socket), host->ssl_)
    , remote_socket_(*context) {
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
        if (!SSL_set_tlsext_host_name(local_socket_.next_layer().native_handle(), host_name.data())) {
            ec = { static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
            throw boost::system::system_error{ ec };
        }
    }
    local_socket_.binary(true);
}

bool wss_tunnel::remote_to_local() noexcept {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<wss_tunnel> self = shared_from_this();
    remote_socket_.async_receive(boost::asio::buffer(remote_socket_buf_, TCP_BUFFER_SIZE),
        [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
            int by = std::max<int>(-1, ec ? -1 : sz);
            if (by <= 0) {
                close();
                return;
            }

            local_socket_.async_write(boost::asio::buffer(remote_socket_buf_, by),
                [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                    if (ec) {
                        close();
                        return;
                    }
                    remote_to_local();
                });
        });
    return true;
}

bool wss_tunnel::local_to_remote() noexcept {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<wss_tunnel> self = shared_from_this();
    local_socket_.async_read(local_socket_buf_,
        [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
            int by = std::max<int>(-1, ec ? -1 : sz);
            if (by <= 0) {
                close();
                return;
            }

            boost::asio::mutable_buffer buf_ = std::move(local_socket_buf_.data());
            boost::asio::async_write(remote_socket_, buf_,
                [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                    local_socket_buf_.clear();
                    if (ec) {
                        close();
                        return;
                    }
                    local_to_remote();
                });
        });
    return true;
}