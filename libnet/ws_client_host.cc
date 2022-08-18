#include <io_host.h>
#include <tls_client_host.h>
#include <ws_client_host.h>
#include <ws_client_tunnel.h>

ws_client_host::ws_client_host(const std::shared_ptr<io_host>& host, const ws_client_link& link) noexcept
    : enable_shared_from_this()
    , host_(host)
    , link_(link)
    , server_(*host->def()) {

}

ws_client_host::~ws_client_host() noexcept {
    close();
}

void ws_client_host::close() noexcept {
    if (server_.is_open()) {
        boost::system::error_code ec;
        try {
            server_.close(ec);
        }
        catch (std::exception&) {}
    }
}

bool ws_client_host::accept_socket() noexcept {
    if (!server_.is_open()) {
        return false;
    }
    std::shared_ptr< boost::asio::io_context> context = host_->get();
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
    std::shared_ptr<ws_client_host> self = shared_from_this();
    server_.async_accept(*socket.get(), [self, this, socket, context](boost::system::error_code ec) noexcept {
        if (ec) {
            tls_client_host::close_socket(*socket.get());
        }
        else {
            tls_client_host::setsockopt(*socket);
            if (link_.local_nagle) {
                socket->set_option(boost::asio::ip::tcp::no_delay(false), ec);
            }
            else {
                socket->set_option(boost::asio::ip::tcp::no_delay(true), ec);
            }

            std::shared_ptr<ws_client_tunnel> connection_ = make_shared_object<ws_client_tunnel>(self, context, socket);
            if (!connection_->run()) {
                connection_->close();
            }
        }
        accept_socket();
    });
    return true;
}

bool ws_client_host::run() noexcept {
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