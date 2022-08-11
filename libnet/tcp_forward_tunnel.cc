#include <io_host.h>
#include <tls_client_host.h>
#include <tcp_forward_host.h>
#include <tcp_forward_tunnel.h>

bool tcp_forward_tunnel::run() {
    std::shared_ptr<tcp_forward_tunnel> self = shared_from_this();
    try {
        // Make the connection on the IP address we get from a lookup.
        tcp_forward_link& link_ = host_->link_;
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

        boost::asio::ip::tcp::endpoint localEP = local_socket_->remote_endpoint(ec);
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

        remote_socket_.async_connect(io_host::endpoint(link_.remote_host, link_.remote_port),
            [self, this](const boost::system::error_code& ec) {
                if (ec) {
                    abort();
                    return;
                }

                local_to_remote();
                remote_to_local();
            });
        return true;
    }
    catch (std::exception&) {
        return false;
    }
}

void tcp_forward_tunnel::abort() {
    if (!fin_.exchange(true)) {
        finalize();
    }
}

void tcp_forward_tunnel::finalize() {
    tls_client_host::close_socket(remote_socket_);
    tls_client_host::close_socket(*local_socket_.get());
}

tcp_forward_tunnel::~tcp_forward_tunnel() {
    finalize();
}

tcp_forward_tunnel::tcp_forward_tunnel(
    const std::shared_ptr<tcp_forward_host>&          host,
    const std::shared_ptr<boost::asio::io_context>&         context,
    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket)
    : enable_shared_from_this()
    , fin_(false)
    , context_(context)
    , host_(host)
    , local_socket_(socket)
    , remote_socket_(*context) {
    tls_client_host::setsockopt(*socket);

    boost::system::error_code ec;
    if (host->link_.local_nagle) {
        socket->set_option(boost::asio::ip::tcp::no_delay(false), ec);
    }
    else {
        socket->set_option(boost::asio::ip::tcp::no_delay(true), ec);
    }
}

bool tcp_forward_tunnel::remote_to_local() {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<tcp_forward_tunnel> self = shared_from_this();
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

bool tcp_forward_tunnel::local_to_remote() {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<tcp_forward_tunnel> self = shared_from_this();
    local_socket_->async_read_some(boost::asio::buffer(local_socket_buf_, TCP_BUFFER_SIZE),
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