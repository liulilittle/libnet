#pragma once

#include <stdafx.h>
#include <config.h>

class io_host;

class ws_client_host : public std::enable_shared_from_this<ws_client_host> {
    friend class ws_client_tunnel;

public:
    ws_client_host(const std::shared_ptr<io_host>& host, const ws_client_link& link) noexcept;
    ~ws_client_host() noexcept;

public:
    bool                            run() noexcept;
    void                            close() noexcept;

private:
    bool                            accept_socket() noexcept;

private:
    std::shared_ptr<io_host>        host_;
    ws_client_link                  link_;
    boost::asio::ip::tcp::acceptor  server_;
};