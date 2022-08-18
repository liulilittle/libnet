#include <tls_client_host.h>
#include <io_host.h>
#include <ws_host.h>
#include <ws_tunnel.h>

// Construct the stream by moving in the socket.
ws_tunnel::ws_tunnel(const std::shared_ptr<ws_host>&        host,
    const std::shared_ptr<boost::asio::io_context>&         context,
    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
    : enable_shared_from_this()
    , host_(host)
    , context_(context)
    , local_socket_(std::move(*socket.get()))
    , remote_socket_(*context.get())
    , fin_(false)
    , local_ok_(false)
    , remote_ok_(false) {
    auto& socket_ = local_socket_.next_layer();
    tls_client_host::setsockopt(socket_);

    boost::system::error_code ec;
    if (host->link_.local_nagle) {
        socket_.set_option(boost::asio::ip::tcp::no_delay(false), ec);
    }
    else {
        socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    }
    local_socket_.binary(true);
}

ws_tunnel::~ws_tunnel() noexcept {
    finalize();
}

void ws_tunnel::finalize() noexcept {
    local_socket_buf_.clear();
    tls_client_host::close_socket(remote_socket_);
    tls_client_host::close_socket(local_socket_.next_layer());
}

bool ws_tunnel::run() noexcept {
    typedef boost::beast::http::request<boost::beast::http::dynamic_body> http_request;

    if (!open_to_remote()) {
        return false;
    }

    // This buffer is used for reading and must be persisted
    std::shared_ptr<boost::beast::flat_buffer> buffer = make_shared_object<boost::beast::flat_buffer>();

    // Declare a container to hold the response
    std::shared_ptr<http_request> req = make_shared_object<http_request>();

    // Receive the HTTP response
    std::shared_ptr<ws_tunnel> self = shared_from_this();
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

        if (!check_path(host_->link_.path_, req->target())) {
            close();
            return;
        }
        ack_establish(true);
    });
    return true;
}

bool ws_tunnel::check_path(std::string& root_, const boost::beast::string_view& sw_) noexcept {
    if (root_.size() <= 1) {
        return true;
    }

    std::string path_ = "/";
    if (sw_.size()) {
        path_ = ToLower(LTrim(RTrim(std::string(sw_.data(), sw_.size()))));
        if (path_.empty()) {
            return false;
        }
    }

    std::size_t sz_ = path_.find_first_of('?');
    if (sz_ == std::string::npos) {
        sz_ = path_.find_first_of('#');
    }

    if (sz_ != std::string::npos) {
        path_ = path_.substr(0, sz_);
    }

    if (path_.size() < root_.size()) {
        return false;
    }

    std::string lroot_ = ToLower(root_);
    if (path_ == lroot_) {
        return true;
    }

    if (path_.size() == lroot_.size()) {
        return false;
    }

    int ch = path_[lroot_.size()];
    return ch == '/';
}

bool ws_tunnel::open_to_remote() noexcept {
    try {
        ws_link& link_ = host_->link_;
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

        boost::asio::ip::tcp::endpoint localEP = local_socket_.next_layer().remote_endpoint(ec);
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

        std::shared_ptr<ws_tunnel> self = shared_from_this();
        remote_socket_.async_connect(
            boost::asio::ip::tcp::endpoint(io_host::endpoint(link_.remote_host, link_.remote_port)), 
            [self, this](const boost::system::error_code& ec) noexcept {
            if (ec) {
                close();
                return;
            }
            ack_establish(false);
        });
        return true;
    }
    catch (std::exception&) {
        return false;
    }
    return false;
}

int ws_tunnel::ack_establish(bool local) noexcept {
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

void ws_tunnel::close() noexcept {
    if (!fin_.exchange(true)) {
        std::shared_ptr<ws_tunnel> self = shared_from_this();
        local_socket_.async_close(boost::beast::websocket::close_code::normal,
            [self, this](const boost::system::error_code& ec_) noexcept {
                finalize();
            });
        tls_client_host::close_socket(remote_socket_);
    }
}

bool ws_tunnel::local_to_remote() noexcept {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<ws_tunnel> self = shared_from_this();
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

bool ws_tunnel::remote_to_local() noexcept {
    if (!socket_is_open()) {
        return false;
    }

    std::shared_ptr<ws_tunnel> self = shared_from_this();
    remote_socket_.async_read_some(boost::asio::buffer(remote_socket_buf_, TCP_BUFFER_SIZE),
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