#include <stdio.h>
#include <signal.h>
#include <limits.h>
#include <stdafx.h>
#include <io_host.h>

io_host::~io_host() noexcept  {
    close();
}

io_host::io_host(int concurrent) noexcept
    : enable_shared_from_this()
    , protect_(NULL)
    , fin_({ false }) {
    if (concurrent <= 0) {
        concurrent = std::max<int>(1, std::thread::hardware_concurrency());
    }
    concurrent_ = concurrent;
}

void io_host::run() noexcept {
    lock_scope scope_(lock_);
    if (!fin_) {
        if (!def_) {
            def_ = newc();
            if (concurrent_ == 1) {
                list_.push_back(def_);
                return;
            }
        }

        int now_ = list_.size();
        int max_ = concurrent_;
        if (max_ > now_) {
            for (int i = 0, l = max_ - now_; i < l; i++) {
                list_.push_back(newc());
            }
        }
    }
}

std::shared_ptr<boost::asio::io_context> io_host::newc() noexcept {
    std::shared_ptr<io_host> self = shared_from_this();
    std::shared_ptr<boost::asio::io_context> context_ = make_shared_object<boost::asio::io_context>();
    std::thread([self, this, context_] {
        boost::system::error_code ec_;
        boost::asio::io_context::work work_(*context_);

        thread_max_priority();
        context_->run(ec_);
    }).detach();
    return std::move(context_);
}

std::shared_ptr<boost::asio::io_context> io_host::def() noexcept {
    return def_;
}

std::shared_ptr<boost::asio::io_context> io_host::get() noexcept  {
    lock_scope scope_(lock_);
    context_list::iterator tail_ = list_.begin();
    context_list::iterator endl_ = list_.end();
    if (tail_ == endl_) {
        return NULL;
    }
    else if (concurrent_ == 1) {
        return *tail_;
    }

    std::shared_ptr<boost::asio::io_context> context_ = std::move(*tail_);
    list_.erase(tail_);
    list_.push_back(context_);
    return std::move(context_);
}

bool io_host::protect(
    int                                             sockfd,
    const boost::asio::ip::tcp::endpoint&           nat,
    const boost::asio::ip::tcp::endpoint&           src,
    const __in_addr__&                              dstAddr,
    int                                             dstPort) noexcept {
    protect_io_event event_ = protect_;
    if (!event_) {
        return true;
    }

    __in_addr__ addresses_[2];
    fill(addresses_[0], nat);
    fill(addresses_[1], src);
    return event_(
        this,
        sockfd,

        &addresses_[0],
        nat.port(),

        &addresses_[1],
        src.port(),

        const_cast<__in_addr__*>(&dstAddr),
        dstPort);
}

bool io_host::protect(
    int                                             sockfd,
    const boost::asio::ip::tcp::endpoint&           nat,
    const boost::asio::ip::tcp::endpoint&           src,
    const boost::asio::ip::tcp::endpoint&           dst) noexcept {

    __in_addr__ host_;
    fill(host_, dst);
    return protect(sockfd, nat, src, host_, dst.port());
}

void io_host::close() noexcept {
    std::vector<context_ptr> releases_;
    if (!fin_.exchange(true)) {
        lock_scope scope_(lock_);
        if (concurrent_ > 1) {
            context_list::iterator tail_ = list_.begin();
            context_list::iterator endl_ = list_.end();
            for (; tail_ != endl_; ++tail_) {
                releases_.push_back(std::move(*tail_));
            }
        }
        list_.clear();
        releases_.push_back(std::move(def_));
    }
    for (size_t i = 0, l = releases_.size(); i < l; i++) {
        releases_[i]->stop();
    }
}

void io_host::thread_max_priority() noexcept {
#ifdef _WIN32
    SetThreadPriority(GetCurrentProcess(), THREAD_PRIORITY_LOWEST);
#else
    /* Processo pai deve ter prioridade maior que os filhos. */
    setpriority(PRIO_PROCESS, 0, -20);

    /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
    struct sched_param param_;
    param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR

    sched_setscheduler(getpid(), SCHED_RR, &param_);
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param_);
#endif
}

void io_host::process_max_priority() noexcept {
#ifdef _WIN32
    SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
#else
    char path_[260];
    snprintf(path_, sizeof(path_), "/proc/%d/oom_adj", getpid());

    FILE* f = fopen(path_, "ab+");
    if (f) {
        char level_[] = "-17";
        fwrite(level_, 1, sizeof(level_), f);
        fflush(f);
        fclose(f);
    }

    /* Processo pai deve ter prioridade maior que os filhos. */
    setpriority(PRIO_PROCESS, 0, -20);

    /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
    struct sched_param param_;
    param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR
    sched_setscheduler(getpid(), SCHED_RR, &param_);
#endif
}