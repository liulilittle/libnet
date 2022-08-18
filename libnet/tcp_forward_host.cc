#include <io_host.h>
#include <tls_client_host.h>
#include <tcp_forward_host.h>
#include <tcp_forward_tunnel.h>

tcp_forward_host::tcp_forward_host(const std::shared_ptr<io_host>& host, const tcp_forward_link& link) noexcept
    : enable_shared_from_this()
    , host_(host)
    , link_(link)
    , server_(*host->def()) {

}

tcp_forward_host::~tcp_forward_host() noexcept {
    close();
}

bool tcp_forward_host::run() noexcept {
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

void tcp_forward_host::close() noexcept {
    if (server_.is_open()) {
        boost::system::error_code ec;
        try {
            server_.close(ec);
        }
        catch (std::exception&) {}
    }
}

bool tcp_forward_host::accept_socket() noexcept {
    if (!server_.is_open()) {
        return false;
    }
    std::shared_ptr<boost::asio::io_context> context = host_->get();
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
    std::shared_ptr<tcp_forward_host> self = shared_from_this();
    server_.async_accept(*socket.get(), [self, this, socket, context](boost::system::error_code ec) noexcept {
        if (ec) {
            tls_client_host::close_socket(*socket.get());
        }
        else {
            std::shared_ptr<tcp_forward_tunnel> connection_ = make_shared_object<tcp_forward_tunnel>(self, context, socket);
            if (!connection_->run()) {
                connection_->close();
            }
        }
        accept_socket();
    });
    return true;
}