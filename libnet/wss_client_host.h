#pragma once

#include <stdafx.h>
#include <config.h>

class io_host;

class wss_client_host : public std::enable_shared_from_this<wss_client_host> {
    friend class wss_client_tunnel;

public:
    wss_client_host(const std::shared_ptr<io_host>& host, const wss_client_link& link) noexcept;
    ~wss_client_host() noexcept;

public:
    bool                            run() noexcept;
    void                            close() noexcept;

private:
    bool                            accept_socket() noexcept;

private:
    std::shared_ptr<io_host>        host_;
    wss_client_link                 link_;
    boost::asio::ip::tcp::acceptor  server_;
    boost::asio::ssl::context       ssl_;
};