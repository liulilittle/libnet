#pragma once

#include <stdafx.h>
#include <config.h>

class wss_client_host;

class wss_client_tunnel : public std::enable_shared_from_this<wss_client_tunnel> {
    typedef boost::asio::ip::tcp::socket                        sys_socket;
    typedef boost::beast::ssl_stream<sys_socket>                ssl_socket;
    typedef boost::beast::websocket::stream<ssl_socket>         web_socket;

public:
    wss_client_tunnel(
        const std::shared_ptr<wss_client_host>&                 host,
        const std::shared_ptr<boost::asio::io_context>&         context,
        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket);
    ~wss_client_tunnel() noexcept;

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
    std::atomic<bool>                                           fin_;
    std::shared_ptr<boost::asio::io_context>                    context_;
    std::shared_ptr<wss_client_host>                            host_;
    std::shared_ptr<boost::asio::ip::tcp::socket>               local_socket_;
    web_socket                                                  remote_socket_;
    char                                                        local_socket_buf_[TCP_BUFFER_SIZE];
    boost::beast::flat_buffer                                   remote_socket_buf_;
};