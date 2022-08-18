#include <tls_client_host.h>
#include <io_host.h>
#include <ws_client_host.h>
#include <ws_client_tunnel.h>

// Construct the stream by moving in the socket.
ws_client_tunnel::ws_client_tunnel(const std::shared_ptr<ws_client_host>& host,
    const std::shared_ptr<boost::asio::io_context>& context,
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
    : enable_shared_from_this()
    , host_(host)
    , context_(context)
    , local_socket_(socket)
    , remote_socket_(*context.get())
    , fin_(false) {
    tls_client_host::setsockopt(*local_socket_);

    boost::system::error_code ec;
    if (host->link_.local_nagle) {
        local_socket_->set_option(boost::asio::ip::tcp::no_delay(false), ec);
    }
    else {
        local_socket_->set_option(boost::asio::ip::tcp::no_delay(true), ec);
    }
    remote_socket_.binary(true);
}

ws_client_tunnel::~ws_client_tunnel() noexcept {
    finalize();
}

void ws_client_tunnel::finalize() noexcept {
    remote_socket_buf_.clear();
    tls_client_host::close_socket(*local_socket_);
    tls_client_host::close_socket(remote_socket_.next_layer());
}

bool ws_client_tunnel::run() noexcept {
    try {
        ws_client_link& link_ = host_->link_;
        auto& socket_ = remote_socket_.next_layer();

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

        std::shared_ptr<ws_client_tunnel> self = shared_from_this();
        remote_socket_.next_layer().async_connect(
            boost::asio::ip::tcp::endpoint(io_host::endpoint(link_.remote_host, link_.remote_port)),
            [self, this](const boost::system::error_code& ec) noexcept {
                if (ec) {
                    close();
                    return;
                }

                ws_client_link& link_ = host_->link_;
                remote_socket_.async_handshake(link_.host_sni, link_.path_, [self, this](const boost::system::error_code& ec) noexcept {
                    if (ec) {
                        close();
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
    return false;
}

void ws_client_tunnel::close() noexcept {
    if (!fin_.exchange(true)) {
        std::shared_ptr<ws_client_tunnel> self = shared_from_this();
        remote_socket_.async_close(boost::beast::websocket::close_code::normal,
            [self, this](const boost::system::error_code& ec_) {
                finalize();
            });
        tls_client_host::close_socket(*local_socket_.get());
    }
}

bool ws_client_tunnel::local_to_remote() noexcept {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<ws_client_tunnel> self = shared_from_this();
    local_socket_->async_read_some(boost::asio::buffer(local_socket_buf_, TCP_BUFFER_SIZE),
        [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
            int by = std::max<int>(-1, ec ? -1 : sz);
            if (by <= 0) {
                close();
                return;
            }

            remote_socket_.async_write(boost::asio::buffer(local_socket_buf_, by),
                [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                    if (ec) {
                        close();
                        return;
                    }
                    local_to_remote();
                });
        });
    return true;
}

bool ws_client_tunnel::remote_to_local() noexcept {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<ws_client_tunnel> self = shared_from_this();
    remote_socket_.async_read(remote_socket_buf_,
        [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
            int by = std::max<int>(-1, ec ? -1 : sz);
            if (by <= 0) {
                close();
                return;
            }

            boost::asio::mutable_buffer buf_ = std::move(remote_socket_buf_.data());
            boost::asio::async_write(*local_socket_, buf_,
                [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                    remote_socket_buf_.clear();
                    if (ec) {
                        close();
                        return;
                    }
                    remote_to_local();
                });
        });
    return true;
}