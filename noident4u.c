/*
  Copyright (c) 2015, Phil Vachon <phil@vachon.nyc>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  - Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

  - Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include <stdlib.h>
#include <getopt.h>

#include <sys/types.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "list.h"

#ifdef _NI_DEBUG
#define DIAG(__x, ...) printf("DIAG[%d]: " __x "\n", getpid(), ##__VA_ARGS__)
#else
#define DIAG(...)
#endif /* defined(_NI_DEBUG) */

#ifdef _NI_DEBUG_STATE
#define SDIAG(_x, _y) DIAG(#_x " -> " #_y)
#else
#define SDIAG(...)
#endif

#define IDENT_STANDARD_PORT             113
#define IDENT_MAX_EVENTS                10
#define IDENT_MAX_BUF                   1024

struct ident_pending {
    int fd;
    uint64_t timestamp;
    uint32_t addr;
    uint16_t port;
    struct list_entry le;
};

static
LIST_HEAD(_pending);

static
int _epfd = -1;

static
int _listen_sock = -1;

static
bool _daemonize = false;

static
uint16_t _listen_port = IDENT_STANDARD_PORT;

static
char *_ident_response_username = NULL;

/* Default timeout: 60s */
static
uint64_t _timeout_ns = 60ull * 1000 * 1000 * 1000;

static volatile
bool _running = true;

#ifdef _NI_DEBUG_DUMP
static
void dump_hex(void *buf, size_t length)
{
    uint8_t *ptr = buf;

    printf("Dumping %zu bytes at %p\n", length, buf);

    for (size_t i = 0; i < length; i+=16) {
        printf("%16zx: ", i + (size_t)buf);
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02x ", (unsigned)ptr[i + j]);
            } else {
                printf("   ");
            }
        }
        printf(" |");
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%c", isprint(ptr[i + j]) ? (char)ptr[i + j] : '.');
            } else {
                printf(" ");
            }
        }
        printf("|\n");
    }
}
#endif

static
uint64_t timestamp(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static
void _handle_sigint(int signal)
{
    if (_running == false) {
        fprintf(stderr, "User insisted aggressively that we exit!\n");
        exit(EXIT_FAILURE);
    }

    _running = false;
}

static
void close_pending(struct ident_pending *ip)
{
    uint32_t addr = ip->addr;
    DIAG("Closing pending connection from %d.%d.%d.%d:%u",
                            ((addr >> 24) & 0xff),
                            ((addr >> 16) & 0xff),
                            ((addr >> 8) & 0xff),
                            (addr & 0xff),
                            ip->port);

    if (0 > epoll_ctl(_epfd, EPOLL_CTL_DEL, ip->fd, NULL)) {
        perror("epoll_ctl");
    }

    if (0 <= ip->fd) {
        close(ip->fd);
        ip->fd = -1;
    }

    list_del(&ip->le);
    free(ip);
}

static
int add_pending(int new_fd, uint32_t addr, uint16_t port, struct ident_pending **pip)
{
    int ret = -1;
    struct ident_pending *ip = NULL;

    if (NULL == (ip = calloc(1, sizeof(*ip)))) {
        goto done;
    }

    ip->addr = addr;
    ip->port = port;
    ip->timestamp = timestamp();
    ip->fd = new_fd;

    list_append(&_pending, &ip->le);

    *pip = ip;

    ret = 0;
done:
    return ret;
}

static
void check_pending(void)
{
    struct ident_pending *ip, *temp = NULL;
    list_for_each_type_safe(ip, temp, &_pending, le) {
        if (timestamp() - ip->timestamp >= _timeout_ns) {
            /* Close the pending connection */
            DIAG("Timeout.");
            close_pending(ip);
        }
    }
}

static
void close_all_pending(void)
{
    struct ident_pending *ip, *temp = NULL;
    list_for_each_type_safe(ip, temp, &_pending, le) {
        close_pending(ip);
    }
}

static
int parse_ident_request(char *req, size_t bytes, uint16_t *src, uint16_t *dst)
{
    int ret = -1;

    unsigned sp = 0, dp = 0;

    enum parse_state {
        /*
         * Initial state. We do allow whitespace in this state
         */
        PS_START,

        /*
         * Currently parsing server port
         */
        PS_SERVER_PORT,

        /*
         * Currently parsing client port
         */
        PS_CLIENT_PORT,

        /*
         * Expect the comma next
         */
        PS_BEFORE_COMMA,

        /*
         * After the comma (for whitespace)
         */
        PS_AFTER_COMMA,

        /*
         * Expect newline next (seen carriage return)
         */
        PS_NEWLINE,

        /*
         * End has been reached
         */
        PS_END,
    };

    enum parse_state cur_state = PS_START;

    for (size_t i = 0; i < bytes; i++) {
        switch (cur_state) {
        case PS_START: {
                if (req[i] == ' ' || req[i] == '\t') {
                    continue;
                } else {
                    char val = req[i] - '0';
                    if (val >= 0 && val <= 9) {
                        cur_state = PS_SERVER_PORT;
                        SDIAG(PS_START, PS_SERVER_PORT);
                        sp = val;
                    } else {
                        fprintf(stderr, "Unexpected character in ident request in PS_START state. Got value %d.\n", (int)req[i]);
                        goto done;
                    }
                }
            }
            break;
        case PS_SERVER_PORT: {
                char val = req[i] - '0';
                if (val >= 0 && val <= 9) {
                    sp *= 10;
                    sp += val;

                    if (sp > 65535) {
                        fprintf(stderr, "Malformed IDENT request. Got a port number larger than 65,535.\n");
                        goto done;
                    }
                } else if (req[i] == ' ' || req[i] == '\t') {
                    SDIAG(PS_SERVER_PORT, PS_BEFORE_COMMA);
                    cur_state = PS_BEFORE_COMMA;
                } else if (req[i] == ',') {
                    SDIAG(PS_SERVER_PORT, PS_AFTER_COMMA);
                    cur_state = PS_AFTER_COMMA;
                } else {
                    fprintf(stderr, "Unexpected character in ident request in PS_SERVER_PORT state. Got value %d.\n", (int)req[i]);
                    goto done;
                }
            }
            break;
        case PS_BEFORE_COMMA: {
                if (req[i] == ' ' || req[i] == '\t') {
                    continue;
                } else if (req[i] == ',') {
                    SDIAG(PS_BEFORE_COMMA, PS_AFTER_COMMA);
                    cur_state = PS_AFTER_COMMA;
                } else {
                    fprintf(stderr, "Unexpected character in ident request in PS_BEFORE_COMMA state. Got value %d.\n", (int)req[i]);
                    goto done;
                }
            }
            break;
        case PS_AFTER_COMMA: {
                char val = req[i] - '0';
                if (req[i] == ' ' || req[i] == '\t') {
                    continue;
                } else if (val >= 0 && val <= 9) {
                    SDIAG(PS_AFTER_COMMA, PS_CLIENT_PORT);
                    cur_state = PS_CLIENT_PORT;
                    dp = val;
                } else {
                    fprintf(stderr, "Unexpected character in ident request in PS_AFTER_COMMA state. Got value %d.\n", (int)req[i]);
                    goto done;
                }
            }
            break;
        case PS_CLIENT_PORT: {
                char val = req[i] - '0';
                if (val >= 0 && val <= 9) {
                    dp *= 10;
                    dp += val;
                } else if (req[i] == '\r') {
                    SDIAG(PS_CLIENT_PORT, PS_NEWLINE);
                    cur_state = PS_NEWLINE;
                } else {
                    fprintf(stderr, "Unexpected character in ident request in PS_CLIENT_PORT state. Got value %d.\n", (int)req[i]);
                    goto done;
                }
            }
            break;
        case PS_NEWLINE:
            if (req[i] != '\n') {
                fprintf(stderr, "Unexpected character in ident request in PS_NEWLINE state. Got value %d.\n", (int)req[i]);
                goto done;
            } else {
                SDIAG(PS_NEWLINE, PS_END);
                cur_state = PS_END;
            }
            break;
        }

        if (cur_state == PS_END) {
            *src = sp;
            *dst = dp;
            break;
        }
    }

    ret = 0;
done:
    return ret;
}

static
int handle_read(struct ident_pending *ip)
{
    int ret = -1;
    int amt_read = -1;
    uint8_t buf[IDENT_MAX_BUF];
    uint16_t src = 0, dst = 0;
    int len = 0;
    char *response = NULL;

    if (0 > (amt_read = read(ip->fd, buf, IDENT_MAX_BUF))) {
        perror("read");
        goto done;
    }

#ifdef _NI_DEBUG_DUMP
    dump_hex(buf, amt_read);
#endif

    if (0 > (ret = parse_ident_request(buf, amt_read, &src, &dst))) {
        goto done;
    }

    fprintf(stderr, "IDENT request from %d.%d.%d.%d:%u for %u -> %u\n",
                            ((ip->addr >> 24) & 0xff),
                            ((ip->addr >> 16) & 0xff),
                            ((ip->addr >> 8) & 0xff),
                            (ip->addr & 0xff),
                            ip->port,
                            src,
                            dst);

    if (0 > (len = asprintf(&response, "%u, %u : USERID : UNIX : %s\r\n", (unsigned)src, (unsigned)dst, _ident_response_username))) {
        perror("asprintf");
        goto done;
    }

    if (0 > send(ip->fd, response, len, 0)) {
        perror("send");
        goto done;
    }

    ret = 0;
done:
    if (NULL != response) {
        free(response);
        response = NULL;
    }
    return ret;
}

static
int run_loop(void)
{
    struct epoll_event evs[IDENT_MAX_EVENTS];

    do {
        int nr_ev = 0;

        if (0 > (nr_ev = epoll_wait(_epfd, evs, IDENT_MAX_EVENTS, 500))) {
            if (errno != EINTR) {
                perror("epoll_wait");
                break;
            } else {
                continue;
            }
        }

        if (0 < nr_ev) {
            for (int i = 0; i < nr_ev; i++) {
                struct epoll_event *ev = &evs[i];

                if (ev->data.fd == _listen_sock) {
                    /* New connection; accept it */
                    struct epoll_event epev;
                    int accept_fd = -1;
                    struct sockaddr_in sin;
                    socklen_t slen = sizeof(sin);
                    uint32_t addr = 0;
                    struct ident_pending *ip = NULL;

                    memset(&sin, 0, sizeof(sin));

                    if (0 > (accept_fd = accept4(_listen_sock, (struct sockaddr *)&sin, &slen, SOCK_NONBLOCK))) {
                        if (errno == ECONNABORTED || errno == ENOMEM) {
                            /* Skip this pending accept4 */
                            continue;
                        } else if (errno == ENFILE || errno == EMFILE) {
                            fprintf(stderr, "Warning: you are out of file descriptors for this process.\n");
                            continue;
                        } else {
                            perror("accept4");
                            exit(EXIT_FAILURE);
                        }
                    }

                    addr = sin.sin_addr.s_addr;

                    DIAG("Accepting ident connection from %d.%d.%d.%d:%u",
                            ((addr >> 24) & 0xff),
                            ((addr >> 16) & 0xff),
                            ((addr >> 8) & 0xff),
                            (addr & 0xff),
                            ntohs(sin.sin_port));

                    if (0 > add_pending(accept_fd, ntohl(addr), ntohs(sin.sin_port), &ip)) {
                        fprintf(stderr, "Error accepting connection from host - could not create pending record.\n");
                        close(accept_fd);
                        continue;
                    }

                    epev.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
                    epev.data.ptr = ip;

                    if (0 > epoll_ctl(_epfd, EPOLL_CTL_ADD, accept_fd, &epev)) {
                        perror("epoll_ctl");
                        close_pending(ip);
                    }
                } else {
                    struct ident_pending *ip = NULL;

                    ip = ev->data.ptr;

                    if (ev->events & EPOLLIN) {
                        /* Handle read and parse */
                        if (0 > handle_read(ip)) {
                            close_pending(ip);
                            continue;
                        }
                    } 
                   
                    if (ev->events & EPOLLHUP || ev->events & EPOLLRDHUP) {
                        close_pending(ip);
                        continue;
                    }
                }
            }
        }

        check_pending();
    } while (_running);
}

static
void close_sockets(void)
{
    if (_epfd >= 0) {
        close(_epfd);
        _epfd = -1;
    }

    if (_listen_sock >= 0) {
        close(_listen_sock);
        _listen_sock = -1;
    }
}

static
int set_up_sockets(void)
{
    int ret = -1;

    struct sockaddr_in sin;
    struct epoll_event epev;

    if (0 > (_epfd = epoll_create1(0))) {
        perror("epoll_create1");
        goto done;
    }

    if (0 > (_listen_sock = socket(AF_INET, SOCK_STREAM, 0))) {
        perror("socket");
        goto done;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(_listen_port);
    sin.sin_addr.s_addr = INADDR_ANY;

    if (0 > bind(_listen_sock, (struct sockaddr *)&sin, sizeof(sin))) {
        perror("bind");
        goto done;
    }

    if (0 > listen(_listen_sock, 10)) {
        perror("listen");
        goto done;
    }

    memset(&epev, 0, sizeof(epev));

    epev.events = EPOLLIN | EPOLLERR;
    epev.data.fd = _listen_sock;

    if (0 > epoll_ctl(_epfd, EPOLL_CTL_ADD, _listen_sock, &epev)) {
        perror("epoll_ctl");
        goto done;
    }

    ret = 0;
done:
    if (0 > ret) {
        close_sockets();
    }
    return ret;
}

static
void daemonize(void)
{
    pid_t new_pid = 0, new_sid = 0;

    if (getppid() == 1) {
        DIAG("Process is already daemonized, skipping.");
        return;
    }

    new_pid = fork();

    if  (new_pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (new_pid > 0) {
        DIAG("Detaching parent from child process.");
        exit(EXIT_SUCCESS);
    }

    if (0 > (new_sid = setsid())) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    if (0 > chdir("/")) {
        perror("chdir");
        exit(EXIT_FAILURE);
    }

    /* We are now daemonized */
}

static
void handle_opts(int argc, char *argv[])
{
    int opt = -1;

    while (-1 != (opt = getopt(argc, argv, "dp:u:"))) {
        switch (opt) {
        case 'd':
            _daemonize = true;
            break;
        case 'p':
            _listen_port = atoi(optarg);
            break;
        case 'u':
            _ident_response_username = strdup(optarg);
            break;
        default:
            fprintf(stderr, "Unknown argument flag: '%c'\n", (char)opt);
        }
    }

    if (NULL == _ident_response_username) {
        _ident_response_username = strdup("noident4u");
    }
}

int main(int argc, char *argv[])
{
    handle_opts(argc, argv);

    if (_daemonize) {
        daemonize();
    }

    fprintf(stderr, "Starting noident4u identd alternative and logger\n");
    DIAG("Username will be %s", _ident_response_username);

    if (SIG_ERR == signal(SIGINT, _handle_sigint)) {
        perror("signal");
        return EXIT_FAILURE;
    }

    if (0 > set_up_sockets()) {
        return EXIT_FAILURE;
    }

    run_loop();

    close_all_pending();

    close_sockets();

    return EXIT_SUCCESS;
}

