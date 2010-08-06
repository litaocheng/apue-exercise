/*
 * a trivial epoll echo server
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/epoll.h>

/*
 * macros
 */
#define ECHO_SEND_SIZE 8192
#define ECHO_RECV_SIZE 8192
#define SEND_TIMEOUT 10
#define RECV_TIMEOUT 10

#define SRV_PORT 2378
#define SRV_BACKLOG 511

#define EPOLL_EVENT_HINTS   128
#define EPOLL_EVENT_INIT    128
#define EPOLL_EVENT_MAX     32000

#define ECHO_REQUEST_MAX_SIZE    10240
#define ECHO_SEND_BUF_SIZE 1024
#define ECHO_RECV_BUF_SIZE 1024

#define VERBOSE_ERROR 1
#define VERBOSE_WARN  2
#define VERBOSE_DEBUG 3

/*
 *  globals
 */

int verbose = VERBOSE_DEBUG;

inline void verbose_out(const char * tag)
{
    char buf[64];
    time_t now;
    now = time(NULL); 
    strftime(buf, 64, "%F %T", localtime(&now)); 
    fprintf(stderr, "[%d] %s *%s* ", (int)getpid(), buf, tag);
}

/* error msg */
inline void error(const char * fmt, ...)
{
    if (verbose >= VERBOSE_ERROR) {
        verbose_out("E");

        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

/* warn msg */
inline void warn(const char * fmt, ...)
{
    if (verbose >= VERBOSE_WARN) {
        verbose_out("W");
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

/* debug msg */
inline void debug(const char * fmt, ...)
{
    if (verbose >= VERBOSE_DEBUG)
    {
        verbose_out("D");
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stdout, fmt, ap);
        va_end(ap);
    }
}

/* 
 * structs
 */

typedef int (*callback_fn)(int fd, int event, void * arg);

struct handler_st {
    bool inpoll;
    int fd;
    int mask;
    callback_fn fn;
    void * arg;
};

/* epoll state struct */
struct epoll_state_st {
    int epfd;       /* the epoll descriptor */

    struct epoll_event * events; /* the events array */
    int nevents;                 /* the events coount */

    struct handler_st * handlers;
    int nhandlers;
};

struct conn_st {
    int     fd;
    void *  server;

    enum {
        ECHO_CONN_IDLE,
        ECHO_CONN_RECV,
        ECHO_CONN_SEND
    } state;

    enum {
        ECHO_RECV_NONE,
        ECHO_RECV_DATA
    } recv_state;

    char *  recv_buf_ptr;
    size_t  recv_buf_size;
    size_t  recv_buf_offset;

    char *  send_buf_ptr;
    size_t  send_buf_size;
    size_t  send_buf_offset;
    size_t  send_data_len;

    struct conn_st * prev;
    struct conn_st * next;

    char    recv_buf[ECHO_RECV_BUF_SIZE];
    char    send_buf[ECHO_SEND_BUF_SIZE];
};

struct server_st {
    int fd;

    struct addrinfo * addr;
    struct addrinfo * addr_next;

    struct epoll_state_st * ep_state;

    struct sockaddr_in  sa_local;

    /* about conns */
    struct conn_st * conn_list;
    size_t  conn_count;
};

/* prototypes */
static void server_freeaddr(struct server_st * serv);
static void server_close(struct server_st * serv);
static int server_accept_handler_add(struct server_st * serv);
static int accept_conn(int fd, int event, void * arg);

static struct handler_st * get_handler(struct server_st * serv, int fd);

static struct conn_st * conn_new(struct server_st * serv, int fd);
static int conn_request(int fd, int event, void * arg);
static int conn_response(int fd, int event, void * arg);
static void conn_close(struct conn_st * conn);
static int conn_buffer_extend(char ** buf, size_t size, bool use_realloc);
        

/*
 * 
 * about the epoll
 *
 */
static int epoll_init(struct epoll_state_st * ep)
{
    debug("epoll init %p\n", ep);
    if (ep == NULL) return -1;

    if ((ep->epfd = epoll_create(EPOLL_EVENT_HINTS)) == -1) {
        error("epoll_create error:%s\n", strerror(errno));
        return -1;
    }

    /* alloc events */
    ep->events = malloc(EPOLL_EVENT_INIT * sizeof(struct epoll_event));
    if (ep->events == NULL) {
        error("oom alloc events");
        return -1;
    }
    ep->nevents = EPOLL_EVENT_INIT;

    /* alloc event handlers */
    ep->handlers = calloc(EPOLL_EVENT_INIT, sizeof(struct handler_st));
    if (ep->handlers == NULL) {
        error("oom alloc handler_st");
        return -1;
    }
    ep->nhandlers = EPOLL_EVENT_INIT;

    return 0;
}

/* initilise the handler */
static int handler_set(struct handler_st * handler, 
        int fd, int mask, 
        callback_fn cb, void * arg)
{
    if (handler == NULL) {
        return -1;
    }

    assert(fd != -1);

    handler->fd = fd;
    handler->mask = mask;
    handler->fn = cb;
    handler->arg = arg;

    return 0;
}


static int epoll_add(struct epoll_state_st * ep, struct handler_st * handler)
{
    int op;
    struct epoll_event epev = {0, {0}};

    if (!ep || !ep->events || !ep->handlers || !handler) {
         return -1; 
    }
    assert(handler->fd != -1);

    /* need more handlers */
    if (handler->fd + 1 > ep->nhandlers) {
        warn("need more handler space\n");
        return -1;
    }

    epev.events = handler->mask;
    epev.data.ptr = handler;

    op = handler->inpoll? EPOLL_CTL_MOD: EPOLL_CTL_ADD;
    if (epoll_ctl(ep->epfd, op, handler->fd, &epev) == -1) {
        error("epoll_ctl error: %s\n", strerror(errno));
        return -1;
    }
    handler->inpoll = true;
    return 0;
}

static int epoll_del(struct epoll_state_st * ep, struct handler_st * handler)
{
    struct epoll_event epev = {0, {0}};

    if (!ep || !ep->events || !ep->handlers || !handler) {
         return -1; 
    }
    assert(handler->fd != -1);

    epev.events = handler->mask;
    epev.data.ptr = handler;

    if (epoll_ctl(ep->epfd, EPOLL_CTL_DEL, handler->fd, &epev) == -1) {
        error("%s error: %s\n", __func__, strerror(errno));
        return -1;
    }

    handler->inpoll = false;
    handler->fd = -1;
    handler->mask = 0;
    handler->fn = NULL;
    handler->arg = NULL;
    return 0;
}

static void epoll_destroy(struct epoll_state_st * ep)
{
    if (!ep) return;

    if (ep->epfd != -1) {
        close(ep->epfd);
    }

    if (ep->events) {
        free(ep->events);
    }
    ep->nevents = 0;
}

/*
 *  about the server
 */

static void server_freeaddr(struct server_st * serv)
{
    if (!serv) return;

    if (serv->addr) {
        freeaddrinfo(serv->addr);
        serv->addr = serv->addr_next = NULL;
    }
}

static void server_close(struct server_st * serv)
{
    if (!serv) return;

    if (serv->fd == -1) return;

    close(serv->fd);
    serv->fd = -1;

    server_freeaddr(serv);
}

static struct handler_st * get_handler(struct server_st * serv, int fd)
{
    struct handler_st * handler;

    if (!serv || !serv->ep_state || !serv->ep_state->handlers) 
        return NULL;

    if (fd == -1)
        return NULL;

    handler = &(serv->ep_state->handlers[fd]);
    return handler;
}

static int server_accept_handler_add(struct server_st * serv)
{
    debug("add accept handler to epoll\n");
    struct handler_st * handler;

    if (!serv) return -1;

    handler = get_handler(serv, serv->fd);
    assert(handler);

    handler_set(handler, serv->fd, EPOLLIN, accept_conn, (void*)serv);

    if (epoll_add(serv->ep_state, handler) != 0) {
        return -1;
    }

    return 0;
}

/*
 * init the server
 */
int server_init(struct server_st * serv)
{
    struct epoll_state_st * ep;
    int ret;

    if (!serv) return -1;

    serv->fd = -1;
    serv->addr = NULL;
    serv->addr_next = NULL;

    /* the epoll */
    ep = calloc(1, sizeof(struct epoll_state_st));
    if (ep == NULL) {
        error("oom");
        return -1;
    }
    
    if(epoll_init(ep) != 0) {
        free(ep);
        return -1;
    }
    serv->ep_state = ep;

    return 0;
}

int server_setup(struct server_st * serv, uint16_t port)
{
    int fd, ret;
    char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    struct addrinfo hints;
    struct sockaddr_in * sin;

    if (!serv) return -1;

    snprintf(port_str, NI_MAXSERV, "%hu", port);

    /* get the server addr */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    while (1) {
        if((ret = getaddrinfo(NULL, port_str, &hints, &serv->addr)) != 0) {
            if (errno == EAI_AGAIN)
                continue;

            error("getaddrinfo for service %s error %d!", port_str, errno);
            return -1;
        }
        break;
    }

    assert(serv->addr);
    serv->addr_next = serv->addr;

    /* create the socket */
    while (serv->addr_next) {
        fd = socket(serv->addr_next->ai_family, 
                serv->addr_next->ai_socktype,
                serv->addr_next->ai_protocol);
        if (fd == -1) {
            error("create socket error%s\n", strerror(errno));
            serv->addr_next = serv->addr_next->ai_next;
            continue;
        }
        
        /* socket create ok */
        break;
    }

    assert(fd);
    serv->fd = fd;
    /* set the socket opts */
    if (_setsockopt(serv) != 0) {
        server_close(serv);
        return -1;
    }
    ret = 1;
    if (setsockopt(serv->fd, SOL_SOCKET, SO_REUSEADDR,
                &ret, (socklen_t)sizeof(int)) == -1) {
        error("SO_REUSEADDR error:%s\n", strerror(errno));
        server_close(serv);
        return -1;
    }

    /* bind */
    sin = (struct sockaddr_in *)serv->addr_next->ai_addr;
    if (!inet_ntop(serv->addr_next->ai_family, &sin->sin_addr,
            host_str, NI_MAXHOST)) {
        error("inet_ntop error: %s\n", strerror(errno));
        server_close(serv);
        return -1;
    }

    debug("bind on %s:%d\n", host_str, port);
    if (bind(serv->fd, serv->addr_next->ai_addr, serv->addr_next->ai_addrlen) == -1) {
        error("bind error :%s\n", strerror(errno));
        server_close(serv);
        return -1;
    }

    /* listen */
    if (listen(serv->fd, SRV_BACKLOG) == -1) {
        error("listen error: %s\n", strerror(errno));
        server_close(serv);
        return -1;
    }
}


/* accept new connection */
static int accept_conn(int fd, int event, void * arg)
{
    struct server_st * serv = arg;
    int client_fd;
    struct conn_st * conn;
    socklen_t len;

    while (1) {
        len = sizeof(serv->sa_local);
        client_fd = accept(fd, (struct sockaddr*)&serv->sa_local, &len);
        if (client_fd == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                error("accetp error:%s\n", strerror(errno));
                return -1;
            }
        }
        break;
    }

    /* handler the client sock */
    debug("client_fd: %d peer %s:%d\n", client_fd, 
            inet_ntoa(serv->sa_local.sin_addr), ntohs(serv->sa_local.sin_port));

    conn = conn_new(serv, client_fd);
    if (!conn) {
        error("conn_new error!\n");
        return 0;
    }

    return 0;
}

static struct conn_st * conn_new(struct server_st * serv, int fd)
{
    debug("%s fd :%d\n", __func__, fd);
    struct conn_st * conn;
    struct handler_st * handler;

    conn = calloc(1, sizeof(struct conn_st));
    if (conn == NULL) {
        error("oom for conn_st\n");
        close(fd);
        return NULL;
    }

    conn->fd = fd;
    conn->server = serv;
    conn->state = ECHO_CONN_IDLE;
    conn->recv_state = ECHO_RECV_NONE;

    conn->send_buf_ptr = conn->send_buf;
    conn->send_buf_size = ECHO_SEND_BUF_SIZE;

    conn->recv_buf_ptr = conn->recv_buf;
    conn->recv_buf_size = ECHO_RECV_BUF_SIZE;

    if (serv->conn_list) {
        serv->conn_list->prev = conn;
    }
    conn->prev = NULL;
    conn->next = serv->conn_list;
    serv->conn_list = conn;
    serv->conn_count++;

    /* add event */
    handler = get_handler(serv, fd);
    assert(handler);
    debug("%s add the client fd to epoll\n", __func__);
    handler_set(handler, fd, EPOLLIN | EPOLLET, conn_request, (void*)conn);
    if (epoll_add(serv->ep_state, handler) != 0) {
        error("epoll_add error:%s\n", strerror(errno));
        free(conn);
        return NULL;
    }

    return conn;
}

static int conn_request(int fd, int event, void * arg)
{
    int nread;
    char * buf;
    size_t buf_size;
    struct conn_st * conn = arg;

    debug("%s :%d\n", __func__, fd);
    assert(event & EPOLLIN);
    assert(arg);

    conn->recv_state = ECHO_RECV_DATA;

    buf = conn->recv_buf_ptr + conn->recv_buf_offset;
    buf_size = conn->recv_buf_size - conn->recv_buf_offset;

    debug("%s fd:%d buf:%p buf_size:%d\n", __func__, fd, buf, buf_size);
    while (1) {
        nread = read(fd, buf, buf_size);
        if (nread == 0) {
            error("the client close the connections!\n");
            conn_close(conn);
            return -1;
        } else if (nread == -1) {
            if (errno == EINTR) 
                continue;

            error("the connection error:%s\n", strerror(errno));
            conn_close(conn);
            return -1;
        } else {
            conn->recv_buf_offset += nread;
            if (conn->recv_buf_offset > ECHO_REQUEST_MAX_SIZE) {
                error("the reqeust is too big!\n");
                conn_close(conn);
                return -1;
            }

            if (conn->recv_buf_offset == conn->recv_buf_size) {
                size_t new_size = conn->recv_buf_size * 2;
                debug("the recv buffer is full, need to extend\n");
                if (conn_buffer_extend(&conn->recv_buf_ptr, new_size,
                        conn->recv_buf_ptr == conn->recv_buf? false: true) != 0) {
                    conn_close(conn);
                    return -1;
                }
                conn->recv_buf_size = new_size;
                return 0;
            }
            break;
        }
    }

    /* handler the request */
    debug("find the \\n in the request\n");
    if (memrchr(conn->recv_buf_ptr, '\n', nread)) {
        struct handler_st * handler;
        struct server_st * server = conn->server;

        if (conn->recv_buf_offset > conn->send_buf_size) {
            /* need extend */
            bool realloc = conn->send_buf_ptr == conn->send_buf? false: true;
            if (conn_buffer_extend(&conn->send_buf_ptr, conn->recv_buf_size, realloc) != 0) {
                conn_close(conn);
                return -1;
            }
            conn->send_buf_size = conn->recv_buf_size;
        }

        /* copy the recvived data to send buffer */
        memcpy(conn->send_buf_ptr, conn->recv_buf_ptr, conn->recv_buf_offset);
        conn->send_data_len = conn->recv_buf_offset;

        conn->recv_buf_offset = 0;
        conn->recv_state = ECHO_RECV_NONE;

        /* add event */
        handler = get_handler(server, fd);
        assert(handler);
        handler_set(handler, fd, EPOLLOUT, conn_response, (void*)conn);
        if (epoll_add(server->ep_state, handler) != 0) {
            error("epoll_add error:%s\n", strerror(errno));
            conn_close(conn);
            return -1;
        }
    }

    return 0;
}

static int conn_response(int fd, int event, void * arg)
{
    char * buf;
    size_t nwrite, remain;
    struct conn_st * conn = arg;
    
    buf = conn->send_buf_ptr + conn->send_buf_offset;
    remain = conn->send_data_len - conn->send_buf_offset;
    debug("%s buf:%p remain:%d\n", __func__, buf, remain);
    
    while (1) {
        nwrite = write(fd, buf, remain);
        if (nwrite == -1) {
            if (errno == EINTR)
                continue;

            error("write to %d error: %s\n", fd, strerror(errno));
            conn_close(conn);
            return -1;
        } else {
            conn->send_buf_offset += nwrite;
            break;
        }
    }

    if (conn->send_buf_offset == conn->send_data_len) {
        struct handler_st * handler;
        struct server_st * serv = conn->server;
        debug("all the data send out!\n");
        conn->send_buf_offset = 0;
        conn->send_data_len = 0;
        conn->state = ECHO_CONN_IDLE;

        /* change event */
        handler = get_handler(serv, fd);
        assert(handler);
        debug("%s change the client fd event to EPOLLIN\n", __func__);
        handler_set(handler, fd, EPOLLIN, conn_request, (void*)conn);
        if (epoll_add(serv->ep_state, handler) != 0) {
            error("epoll_add error:%s\n", strerror(errno));
            free(conn);
            return -1;
        }

    }

    return 0;
}

static void conn_close(struct conn_st * conn)
{
    struct server_st * serv;
    struct handler_st * handler;
    if (!conn) return;

    serv = conn->server;
    if (conn->fd != -1) {
        handler = get_handler(serv, conn->fd);
        if (handler) {
            epoll_del(serv->ep_state, handler);
        }

        close(conn->fd);
        conn->fd = -1;
    }

    if (conn->send_buf_ptr != conn->send_buf) {
        free(conn->send_buf_ptr);
        conn->send_buf_ptr = NULL;
    }

    if (conn->recv_buf_ptr != conn->recv_buf) {
        free(conn->recv_buf_ptr);
        conn->recv_buf_ptr = NULL;
    }

    if (conn->prev)
        conn->prev->next = conn->next;
    if (conn->next)
        conn->next->prev = conn->prev;

    if (serv->conn_list == conn)
        serv->conn_list = conn->next;
}

static int conn_buffer_extend(char ** buf, size_t size, bool use_realloc)
{
    char * p = *buf;
    if (realloc) {
        p = realloc(p, size);
    } else {
        p = malloc(size);
    }


    if (p == NULL) {
        error("oom");
        return -1;
    }
    *buf = p;
    return 0;
}



void server_destroy(struct server_st * serv)
{
    if (!serv) return;

    if (serv->fd)
    {
        close(serv->fd);
    }

    if (serv->ep_state) {
        epoll_destroy(serv->ep_state);
        free(serv->ep_state); 
        serv->ep_state = NULL;
    }
}

/*
 * set the sock opts
 */
int _setsockopt(struct server_st * serv)
{
    int ret;
    struct timeval tv;

    if (!serv || !serv->fd) {
        error("server invalid");
        return ret;
    }

    /* set nodelay */
    ret = 1;
    ret = setsockopt(serv->fd, IPPROTO_TCP, TCP_NODELAY, 
            &ret, (socklen_t)sizeof(int));
    if (ret == -1) {
        error("setsockopt TCP_NODELAY error:%d", errno);
        return -1;
    }

    /* set the send buf */
    ret = ECHO_SEND_SIZE;
    ret = setsockopt(serv->fd, SOL_SOCKET, SO_SNDBUF,
            &ret, (socklen_t)sizeof(int));
    if (ret == -1) {
        error("setsockopt SO_SNDBUF error:%s\n", strerror(errno));
        return -1;
    }

    /* set the recv buf */
    ret = ECHO_RECV_SIZE;
    ret = setsockopt(serv->fd, SOL_SOCKET, SO_RCVBUF,
            &ret, (socklen_t)sizeof(int));
    if (ret == -1) {
        error("setsockopt  SO_RCVBUF error:%s\n", strerror(errno));
        return -1;
    }

    /* set the send timeout */
    tv.tv_sec = SEND_TIMEOUT;
    tv.tv_usec = 0;
    ret = setsockopt(serv->fd, SOL_SOCKET, SO_SNDTIMEO,
            &tv, (socklen_t)sizeof(struct timeval));
    if (ret == -1) {
        error("setsockopt SO_SNDTIMEO error:%s\n", strerror(errno));
        return -1;
    }
    
    /* set the recv timeout */
    tv.tv_sec = RECV_TIMEOUT;
    tv.tv_usec = 0;
    ret = setsockopt(serv->fd, SOL_SOCKET, SO_RCVTIMEO,
            &tv, (socklen_t)sizeof(struct timeval));
    if (ret == -1) {
        error("setsockopt SO_RCVTIMEO error:%s\n", strerror(errno));
        return -1;
    }

    /* set non-blocking */
    ret = fcntl(serv->fd, F_GETFL, 0);
    if (ret == -1) {
        error("F_GETFL error:%d", errno);
        return -1;
    }
    ret = fcntl(serv->fd, F_SETFL, ret | O_NONBLOCK);
    if (ret == -1) {
        error("F_SETFL error:%d", error);
        return -1;
    }
    return ret;
}

/*
 * get the server addrinfo
 */
int server_addinfo(struct server_st * serv)
{
    return -1;
}



int main(int argc, char * argv[])
{
    struct server_st server;
    struct handler_st * handler;

    /* init the server  */
    memset(&server, 0, sizeof(server));

    if (server_init(&server) != 0) {
        error("the servr initialise error\n");
        exit(1);
    }

    debug("server setup now\n");
    if (server_setup(&server, SRV_PORT) != 0) {
        error("server setup error!\n");
        exit(1);
    }

    debug("add listen sock to epoll\n");
    if (server_accept_handler_add(&server) != 0) {
        server_destroy(&server);
        exit(1);
    }
    
    /* the main loop */
    main_loop(&server);

    /* destroy the server */
    server_destroy(&server);

    return 0;
}


int main_loop(struct server_st * server)
{
    int done = 0;
    int ret, i, fd;
    int events;
    struct epoll_state_st * ep = server->ep_state;
    struct handler_st * handler;

    if (!server) return -1;

    while (!done) {
        ret = epoll_wait(ep->epfd, ep->events, ep->nevents, -1);
        if (ret == 0) {
            warn("no active event\n");
            continue;
        } else if (ret == -1) {
            error("epoll_wait error:%s", strerror(errno));
            return -1;
        }

        debug("epoll_wait return %d\n", ret);
        for (i = 0; i < ret; ++i) {
            events = ep->events[i].events;
            handler =  (struct handler_st *)ep->events[i].data.ptr;
            if (handler->fn) 
            {
                handler->fn(handler->fd, events, handler->arg);
            }
        }
    }
    return 0;
}
