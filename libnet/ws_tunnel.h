#pragma once

#include <stdafx.h>
#include <config.h>

class ws_host;

class ws_tunnel : public std::enable_shared_from_this<ws_tunnel> {
    typedef boost::asio::ip::tcp::socket                        lower_layer_socket;
    typedef boost::beast::websocket::stream<lower_layer_socket> web_socket;

public:
    ws_tunnel(const std::shared_ptr<ws_host>&                   host,
        const std::shared_ptr<boost::asio::io_context>&         context,
        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket);
    ~ws_tunnel();

public:
    bool                                                        run();
    void                                                        abort();
    static bool                                                 check_path(std::string& root_, const boost::beast::string_view& sw_);

private:
    void                                                        finalize();
    bool                                                        open_to_remote();
    bool                                                        local_to_remote();
    bool                                                        remote_to_local();
    int                                                         ack_establish(bool local);
    inline bool                                                 socket_is_open() {
        if (fin_.load()) {
            return false;
        }
        return local_socket_.is_open() && remote_socket_.is_open();
    }

private:
    std::shared_ptr<ws_host>                                    host_;
    std::shared_ptr<boost::asio::io_context>                    context_;
    web_socket                                                  local_socket_;
    boost::asio::ip::tcp::socket                                remote_socket_;
    std::atomic<bool>                                           fin_;
    bool                                                        local_ok_ : 1;
    bool                                                        remote_ok_: 7;
    boost::beast::flat_buffer                                   local_socket_buf_;
    char                                                        remote_socket_buf_[TCP_BUFFER_SIZE];
};