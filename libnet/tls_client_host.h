#pragma once

#include <stdafx.h>
#include <config.h>
#include <io_host.h>

class tls_client_host : public std::enable_shared_from_this<tls_client_host> {
    friend class tls_client_tunnel;

public:
    tls_client_host(const std::shared_ptr<io_host>& host, const tls_client_link& link) noexcept;
    ~tls_client_host() noexcept;

public:
    bool                                        run() noexcept;
    void                                        close() noexcept;

public:
    static void                                 close_socket(boost::asio::ip::tcp::socket& s) noexcept;
    static int                                  ssl_method(int method) noexcept;

public:
    template<typename T>
    inline static void                          setsockopt(T& socket) noexcept {
        boost::system::error_code ec_;
        auto localEP = socket.local_endpoint(ec_);
        
        bool v4_or_v6 = false;
        if (!ec_) {
            v4_or_v6 = localEP.address().is_v4();
        }
        return setsockopt(socket.native_handle(), v4_or_v6);
    }
    static void                                 setsockopt(int sockfd, bool v4_or_v6) noexcept;

public:
    template<typename T>
    inline static void                          bind_socket(T& socket, const __in_addr__& host) noexcept {
        if (io_host::loopback(host)) {
            if (host.bv6) {
                socket.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::loopback(), 0));
            }
            else {
                socket.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
            }
        }
        else {
            if (host.bv6) {
                socket.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), 0));
            }
            else {
                socket.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), 0));
            }
        }
    }
    template<typename T>
    inline static boost::system::error_code     open_socket(T& socket, const __in_addr__& host) noexcept {
        boost::system::error_code ec;
        if (host.bv6) {
            socket.open(boost::asio::ip::tcp::v6(), ec);
        }
        else {
            socket.open(boost::asio::ip::tcp::v4(), ec);
        }
        return ec;
    }

private:
    bool                            accept_socket() noexcept;

private:
    std::shared_ptr<io_host>        host_;
    tls_client_link                 link_;
    boost::asio::ip::tcp::acceptor  server_;
    boost::asio::ssl::context       ssl_;
};