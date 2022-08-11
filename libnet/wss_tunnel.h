#pragma once

#include <stdafx.h>
#include <config.h>

class wss_host;

class wss_tunnel : public std::enable_shared_from_this<wss_tunnel> {
    typedef boost::asio::ip::tcp::socket                        sys_socket;
    typedef boost::beast::ssl_stream<sys_socket>                ssl_socket;
    typedef boost::beast::websocket::stream<ssl_socket>         web_socket;

public:
    wss_tunnel(
        const std::shared_ptr<wss_host>&                        host,
        const std::shared_ptr<boost::asio::io_context>&         context,
        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket);
    ~wss_tunnel();

public:
    bool                                                        run();
    void                                                        abort();

private:
    void                                                        finalize();
    int                                                         ack_establish(bool local);
    bool                                                        local_to_remote();
    bool                                                        remote_to_local();
    inline bool                                                 socket_is_open() {
        if (fin_.load()) {
            return false;
        }
        return local_socket_.is_open() && remote_socket_.is_open();
    }

private:
    std::atomic<bool>                                           fin_;
    bool                                                        local_ok_ : 1;
    bool                                                        remote_ok_ : 7;
    std::shared_ptr<boost::asio::io_context>                    context_;
    std::shared_ptr<wss_host>                                   host_;
    web_socket                                                  local_socket_;
    boost::asio::ip::tcp::socket                                remote_socket_;
    boost::beast::flat_buffer                                   local_socket_buf_;
    char                                                        remote_socket_buf_[TCP_BUFFER_SIZE];
};