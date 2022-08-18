#pragma once

#include <stdafx.h>

class io_host : public std::enable_shared_from_this<io_host> {
public:
    typedef bool(*protect_io_event)(
        void*                                           iohost, 
        int                                             sockfd, 
        __in_addr__*                                    natAddr,
        int                                             natPort,
        __in_addr__*                                    srcAddr,
        int                                             srcPort, 
        __in_addr__*                                    dstAddr,
        int                                             dstPort);

private:
    typedef std::shared_ptr<boost::asio::io_context>    context_ptr;
    typedef std::list<context_ptr>                      context_list;
    typedef std::mutex                                  lock_obj;
    typedef std::lock_guard<lock_obj>                   lock_scope;

public:
    io_host(int concurrent) noexcept;
    ~io_host() noexcept;

public:
    std::shared_ptr<boost::asio::io_context>            def() noexcept;
    std::shared_ptr<boost::asio::io_context>            get() noexcept;
    void                                                close() noexcept;
    void                                                run() noexcept;
    bool                                                protect(
        int                                             sockfd,
        const boost::asio::ip::tcp::endpoint&           nat,
        const boost::asio::ip::tcp::endpoint&           src,
        const boost::asio::ip::tcp::endpoint&           dst) noexcept;
    bool                                                protect(
        int                                             sockfd,
        const boost::asio::ip::tcp::endpoint&           nat,
        const boost::asio::ip::tcp::endpoint&           src,
        const __in_addr__&                              dstAddr,
        int                                             dstPort) noexcept;
    
public:
    protect_io_event                                    protect_;

public:
    inline static boost::asio::ip::tcp::endpoint        endpoint(const __in6_addr__& in6_, int port) noexcept {
        boost::asio::ip::address_v6::bytes_type host_; // IN6ADDR_ANY_INIT; IN6ADDR_LOOPBACK_INIT
        memcpy(host_.data(), &in6_, host_.size());

        return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6(host_), port);
    }
    inline static boost::asio::ip::tcp::endpoint        endpoint(const __in4_addr__& in4_, int port) noexcept {
        boost::asio::ip::address_v4::uint_type host_ = htonl(in4_);
        return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(host_), port);
    }
    inline static boost::asio::ip::tcp::endpoint        endpoint(const __in_addr__& in_, int port) noexcept {
        if (in_.bv6) {
            return endpoint(in_.in6, port);
        }
        else {
            return endpoint(in_.in4, port);
        }
    }
    inline static bool                                  loopback(const __in_addr__& in_) noexcept {
        if (in_.bv6) {
            const __in6_addr__* a = &in_.in6;
            return ((a->u.word_bin[0] == 0) &&
                (a->u.word_bin[1] == 0) &&
                (a->u.word_bin[2] == 0) &&
                (a->u.word_bin[3] == 0) &&
                (a->u.word_bin[4] == 0) &&
                (a->u.word_bin[5] == 0) &&
                (a->u.word_bin[6] == 0) &&
                (a->u.word_bin[7] == 0x0100));
        }
        return in_.in4 == htonl(INADDR_LOOPBACK);
    }
    inline static bool                                  any(const __in_addr__& in_) noexcept {
        if (in_.bv6) {
            const __in6_addr__* a = &in_.in6;
            return ((a->u.word_bin[0] == 0) &&
                (a->u.word_bin[1] == 0) &&
                (a->u.word_bin[2] == 0) &&
                (a->u.word_bin[3] == 0) &&
                (a->u.word_bin[4] == 0) &&
                (a->u.word_bin[5] == 0) &&
                (a->u.word_bin[6] == 0) &&
                (a->u.word_bin[7] == 0));
        }
        return in_.in4 == htonl(INADDR_ANY);
    }
    static void                                         thread_max_priority() noexcept;
    static void                                         process_max_priority() noexcept;

private:
    std::shared_ptr<boost::asio::io_context>            newc() noexcept;
    inline void                                         fill(__in_addr__& dst, const boost::asio::ip::tcp::endpoint& src) noexcept {
        boost::asio::ip::address adr_ = src.address();
        if (adr_.is_v6()) {
            boost::asio::ip::address_v6::bytes_type abr_ = adr_.to_v6().to_bytes();
            dst.bv6 = 1;
            memcpy(&dst.in6, abr_.data(), abr_.size());
        }
        else {
            dst.bv6 = 0;
            dst.in4 = htonl(adr_.to_v4().to_ulong());
        }
    }

private:
    std::atomic<bool>                                   fin_;
    lock_obj                                            lock_;
    context_list                                        list_;
    context_ptr                                         def_;
    int                                                 concurrent_;
};