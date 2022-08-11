#pragma once

#include <stdafx.h>
#include <config.h>

class io_host;

class tcp_forward_host : public std::enable_shared_from_this<tcp_forward_host> {
    friend class tcp_forward_tunnel;

public:
    tcp_forward_host(const std::shared_ptr<io_host>& host, const tcp_forward_link& link);
    ~tcp_forward_host();

public:
    bool                            run();
    void                            abort();

private:
    bool                            accept_socket();

private:
    std::shared_ptr<io_host>        host_;
    tcp_forward_link          link_;
    boost::asio::ip::tcp::acceptor  server_;
};