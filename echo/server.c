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
#define SEND_SIZE 8192
#define RECV_SIZE 8192
#define SEND_TIMEOUT 10
#define RECV_TIMEOUT 10

#define SRV_PORT 2378
#define SRV_BACKLOG 511

#define EPOLL_EVENT_HINTS   128
#define EPOLL_EVENT_INIT    128
#define EPOLL_EVENT_MAX     32000

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
    fprintf(stderr, "[%d] %s [%s] ", (int)getpid(), buf, tag);
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

struct server_st {
    int fd;

    struct addrinfo * addr;
    struct addrinfo * addr_next;

    struct epoll_state_st * ep_state;
};

/* prototypes */
static void server_freeaddr(struct server_st * serv);
static void server_close(struct server_st * serv);

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
        error("epoll_ctl error!");
        return -1;
    }
    return 0;
}

static int epoll_del()
{

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
    struct addrinfo hints;
    char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];

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
    if (getnameinfo(serv->addr_next->ai_addr, serv->addr_next->ai_addrlen,
        host_str, NI_MAXHOST,
        port_str, NI_MAXSERV,
        0) != 0) {
        error("getname info error:%s\n", strerror(errno));
        server_close(serv);
        return -1;
    }

    debug("bind on %s:%s\n", host_str, port_str);
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
int accept_conn(int fd, int event, void * arg)
{
    debug("new connection %d\n", fd);
    close(fd);
    return -1;
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
    ret = SEND_SIZE;
    ret = setsockopt(serv->fd, SOL_SOCKET, SO_SNDBUF,
            &ret, (socklen_t)sizeof(int));
    if (ret == -1) {
        error("setsockopt SO_SNDBUF error:%s\n", strerror(errno));
        return -1;
    }

    /* set the recv buf */
    ret = RECV_SIZE;
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
    handler = &(server.ep_state->handlers[server.fd]);
    handler_set(handler, server.fd, EPOLLIN, accept_conn, (void*)&server);

    if (epoll_add(server.ep_state, handler) != 0) {
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

        sleep(1);
    }

    return 0;
}
