#pragma once

#include <stdafx.h>
#include <config.h>

class ws_client_host;

class ws_client_tunnel : public std::enable_shared_from_this<ws_client_tunnel> {
    typedef boost::asio::ip::tcp::socket                        lower_layer_socket;
    typedef boost::beast::websocket::stream<lower_layer_socket> web_socket;

public:
    ws_client_tunnel(const std::shared_ptr<ws_client_host>& host,
        const std::shared_ptr<boost::asio::io_context>& context,
        const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
    ~ws_client_tunnel() noexcept;

public:
    bool                                                        run() noexcept;
    void                                                        close() noexcept;

private:
    void                                                        finalize() noexcept;
    bool                                                        local_to_remote() noexcept;
    bool                                                        remote_to_local() noexcept;
    inline bool                                                 socket_is_open() noexcept {
        if (fin_.load()) {
            return false;
        }
        return local_socket_->is_open() && remote_socket_.is_open();
    }

private:
    std::shared_ptr<ws_client_host>                             host_;
    std::shared_ptr<boost::asio::io_context>                    context_;
    std::shared_ptr<boost::asio::ip::tcp::socket>               local_socket_;
    web_socket                                                  remote_socket_;
    std::atomic<bool>                                           fin_;
    boost::beast::flat_buffer                                   remote_socket_buf_;
    char                                                        local_socket_buf_[TCP_BUFFER_SIZE];
};