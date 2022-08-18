#pragma once

#include <stdafx.h>
#include <config.h>

class tls_client_host;

class tls_client_tunnel : public std::enable_shared_from_this<tls_client_tunnel> {
public:
    tls_client_tunnel(
        const std::shared_ptr<tls_client_host>&                 host, 
        const std::shared_ptr<boost::asio::io_context>&         context, 
        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket);
    ~tls_client_tunnel() noexcept;

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
        return local_socket_->is_open() && remote_socket_.lowest_layer().is_open();
    }

private:
    std::atomic<bool>                                           fin_;
    std::shared_ptr<boost::asio::io_context>                    context_;
    std::shared_ptr<tls_client_host>                            host_;
    std::shared_ptr<boost::asio::ip::tcp::socket>               local_socket_;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>      remote_socket_;
    char                                                        local_socket_buf_[TCP_BUFFER_SIZE];
    char                                                        remote_socket_buf_[TCP_BUFFER_SIZE];
};