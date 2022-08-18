#pragma once

#include <stdafx.h>
#include <config.h>

class tcp_forward_host;

class tcp_forward_tunnel : public std::enable_shared_from_this<tcp_forward_tunnel> {
public:
    tcp_forward_tunnel(
        const std::shared_ptr<tcp_forward_host>&                host,
        const std::shared_ptr<boost::asio::io_context>&         context,
        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept;
    ~tcp_forward_tunnel() noexcept;

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
    std::shared_ptr<tcp_forward_host>                           host_;
    std::shared_ptr<boost::asio::ip::tcp::socket>               local_socket_;
    boost::asio::ip::tcp::socket                                remote_socket_;
    char                                                        local_socket_buf_[TCP_BUFFER_SIZE];
    char                                                        remote_socket_buf_[TCP_BUFFER_SIZE];
};