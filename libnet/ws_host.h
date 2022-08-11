#pragma once

#include <stdafx.h>
#include <config.h>

class io_host;

class ws_host : public std::enable_shared_from_this<ws_host> {
    friend class ws_tunnel;

public:
    ws_host(const std::shared_ptr<io_host>& host, const ws_link& link);
    ~ws_host();

public:
    bool                            run();
    void                            abort();

private:
    bool                            accept_socket();

private:
    std::shared_ptr<io_host>        host_;
    ws_link                         link_;
    boost::asio::ip::tcp::acceptor  server_;
};