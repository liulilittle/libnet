#pragma once

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib, "Ws2_32.lib")
#else
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/file.h>
#endif

#include <functional>
#include <mutex>
#include <utility>
#include <memory>
#include <thread>
#include <map>
#include <set>
#include <list>
#include <vector>
#include <unordered_set>
#include <unordered_map>

#include <common.h>
#include <libnet_boost.h>

#ifndef PATH_MAX
#define PATH_MAX 4096/*MAX_PATH*/
#endif

inline int                                                      Tokenize(const std::string& str, std::vector<std::string>& tokens, const std::string& delimiters) noexcept {
    if (str.empty()) {
        return 0;
    }
    else if (delimiters.empty()) {
        tokens.push_back(str);
        return 1;
    }

    char* deli_ptr    = (char*)delimiters.data();
    char* deli_endptr = deli_ptr + delimiters.size();
    char* data_ptr    = (char*)str.data();
    char* data_endptr = data_ptr + str.size();
    char* last_ptr    = NULL;

    int length        = 0;
    int seg           = 0;
    while (data_ptr < data_endptr) {
        int ch = *data_ptr;
        int b = 0;
        for (char* p = deli_ptr; p < deli_endptr; p++) {
            if (*p == ch) {
                b = 1;
                break;
            }
        }
        if (b) {
            if (seg) {
                int sz = data_ptr - last_ptr;
                if (sz > 0) {
                    length++;
                    tokens.push_back(std::string(last_ptr, sz));
                }
                seg = 0;
            }
        }
        else if (!seg) {
            seg = 1;
            last_ptr = data_ptr;
        }
        data_ptr++;
    }
    if ((seg && last_ptr) && last_ptr < data_ptr) {
        length++;
        tokens.push_back(std::string(last_ptr, data_ptr - last_ptr));
    }
    return length;
}
inline std::string                                              LTrim(const std::string& s) noexcept {
    std::string str = s;
    if (str.empty()) {
        return str;
    }
    int64_t pos = -1;
    for (size_t i = 0, l = str.size(); i < l; ++i) {
        char ch = str[i];
        if (ch == ' ' ||
            ch == '\0' ||
            ch == '\n' || 
            ch == '\r' || 
            ch == '\t') {
            pos = i + 1;
        }
        else {
            break;
        }
    }
    if (pos >= 0) {
        if (pos >= (int64_t)str.size()) {
            return "";
        }
        str = str.substr(pos);
    }
    return str;
}
inline std::string                                              RTrim(const std::string& s) noexcept {
    std::string str = s;
    if (str.empty()) {
        return str;
    }
    int64_t pos = -1;
    int64_t i = str.size();
    i--;
    for (; i >= 0u; --i) {
        char ch = str[i];
        if (ch == ' ' ||
            ch == '\0' ||
            ch == '\n' || 
            ch == '\r' || 
            ch == '\t') {
            pos = i;
        }
        else {
            break;
        }
    }
    if (pos >= 0) {
        if (0 >= pos) {
            return "";
        }
        str = str.substr(0, pos);
    }
    return str;
}
inline std::string                                              ToUpper(const std::string& s) noexcept {
    std::string r = s;
    if (!r.empty()) {
        std::transform(s.begin(), s.end(), r.begin(), toupper);
    }
    return r;
}
inline std::string                                              ToLower(const std::string& s) noexcept {
    std::string r = s;
    if (!r.empty()) {
        std::transform(s.begin(), s.end(), r.begin(), tolower);
    }
    return r;
}
inline std::string                                              Replace(const std::string& s, const std::string& old_value, const std::string& new_value) noexcept {
    std::string r = s;
    if (r.empty()) {
        return r;
    }
    do {
        std::string::size_type pos = r.find(old_value);
        if (pos != std::string::npos) {
            r.replace(pos, old_value.length(), new_value);
        }
        else {
            break;
        }
    } while (1);
    return r;
}
inline int                                                      Split(const std::string& str, std::vector<std::string>& tokens, const std::string& delimiters) noexcept {
    if (str.empty()) {
        return 0;
    }
    else if (delimiters.empty()) {
        tokens.push_back(str);
        return 1;
    }
    size_t last_pos = 0;
    size_t curr_cnt = 0;
    while (1) {
        size_t pos = str.find(delimiters, last_pos);
        if (pos == std::string::npos) {
            pos = str.size();
        }

        size_t len = pos - last_pos;
        if (len != 0) {
            curr_cnt++;
            tokens.push_back(str.substr(last_pos, len));
        }

        if (pos == str.size()) {
            break;
        }
        last_pos = pos + delimiters.size();
    }
    return curr_cnt;
}
inline uint64_t                                                 GetTickCount(bool microseconds) noexcept {
#ifdef _WIN32
    static LARGE_INTEGER ticksPerSecond; // (unsigned long long)GetTickCount64();
    LARGE_INTEGER ticks;
    if (!ticksPerSecond.QuadPart) {
        QueryPerformanceFrequency(&ticksPerSecond);
    }
    
    QueryPerformanceCounter(&ticks);
    if (microseconds) {
        double cpufreq = (double)(ticksPerSecond.QuadPart / 1000000);
        unsigned long long nowtick = (unsigned long long)(ticks.QuadPart / cpufreq);
        return nowtick;
    }
    else {
        unsigned long long seconds = ticks.QuadPart / ticksPerSecond.QuadPart;
        unsigned long long milliseconds = 1000 * (ticks.QuadPart - (ticksPerSecond.QuadPart * seconds)) / ticksPerSecond.QuadPart;
        unsigned long long nowtick = seconds * 1000 + milliseconds;
        return (unsigned long long)nowtick;
    }
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);

    if (microseconds) {
        unsigned long long nowtick = (unsigned long long)tv.tv_sec * 1000000;
        nowtick += tv.tv_usec;
        return nowtick;
    }

    return ((unsigned long long)tv.tv_usec / 1000) + ((unsigned long long)tv.tv_sec * 1000);
#endif
}
inline std::string                                              PaddingLeft(const std::string& s, int count, char padding_char) noexcept {
    char buf[1500]; 
    if (count <= 0 || count <= (int)s.size()) {
        return s;
    }
    std::string r = s;
    int len = count - (int)s.size();
    while (len > 0) {
        int rd = len; 
        if (rd >= (int)sizeof(buf)) {
            rd = sizeof(buf);
        }
        memset(buf, padding_char, rd);
        len -= rd;
        r = std::string(buf, rd) + r;
    }
    return r;
}
inline std::string                                              PaddingRight(const std::string& s, int count, char padding_char) noexcept {
    char buf[1500]; 
    if (count <= 0 || count <= (int)s.size()) {
        return s;
    }
    std::string r = s;
    int len = count - (int)s.size();
    while (len > 0) {
        int rd = len; 
        if (rd >= (int)sizeof(buf)) {
            rd = sizeof(buf);
        }
        memset(buf, padding_char, rd);
        len -= rd;
        r = r + std::string(buf, rd);
    }
    return r;
}
inline std::string                                              GetCurrentTimeText() noexcept {
    time_t rawtime;
    struct tm* ptminfo;

    time(&rawtime);
    ptminfo = localtime(&rawtime);

    auto fmt = [](int source, char *dest) {
        if (source < 10) {
            char temp[3];
            strcpy(dest, "0");
            sprintf(temp, "%d", source);
            strcat(dest, temp);
        }
        else {
            sprintf(dest, "%d", source);
        }
    };

    char yyyy[5], MM[3], dd[3], hh[3], mm[3], ss[3];
    sprintf(yyyy, "%d", (ptminfo->tm_year + 1900));

    fmt(ptminfo->tm_mon + 1, MM);
    fmt(ptminfo->tm_mday, dd);
    fmt(ptminfo->tm_hour, hh);
    fmt(ptminfo->tm_min, mm);
    fmt(ptminfo->tm_sec, ss);

    std::string sb;
    sb.append(yyyy).
        append("-").
        append(MM).
        append("-").
        append(dd).
        append(" ").
        append(hh).
        append(":").
        append(mm).
        append(":").
        append(ss);
    return sb;
}
inline std::string                                              ToAddressString(uint32_t address, uint16_t port) noexcept {
    char sz[128]; 
    uint8_t* p = (uint8_t*)&address;
    sprintf(sz, "%d.%d.%d.%d:%d", p[0], p[1], p[2], p[3], port);
    return sz;
}

template<class TProtocol>
inline std::string                                              ToAddressString(const boost::asio::ip::basic_endpoint<TProtocol>& ep) noexcept {
    return std::move(ep.address().to_string() + ":" + std::to_string(ep.port()));
}

template<typename T>
inline std::shared_ptr<T>                                       make_shared_alloc(int length) noexcept {
    static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

    // https://pkg.go.dev/github.com/google/agi/core/os/device
    // ARM64v8a: __ALIGN(8)
    // ARMv7a  : __ALIGN(4)
    // X86_64  : __ALIGN(8)
    // X64     : __ALIGN(4)
    if (length <= 0) {
        return NULL;
    }

    T* p = (T*)::malloc(length * sizeof(T));
    return std::shared_ptr<T>(p, ::free);
}

template<typename T, typename... A>
inline std::shared_ptr<T>                                       make_shared_object(A&&... args) noexcept {
    return std::make_shared<T>(std::forward<A&&>(args)...);
}