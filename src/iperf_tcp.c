/*
 * iperf, Copyright (c) 2014-2022, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <limits.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_tcp.h"
#include "net.h"
#include "cjson.h"
#include <execinfo.h>


#if defined(HAVE_FLOWLABEL)
#include "flowlabel.h"
#endif /* HAVE_FLOWLABEL */

/* iperf_tcp_recv
 *
 * receives the data for TCP
 */
int
iperf_tcp_recv(struct iperf_stream *sp)
{
    int r;


    //Todo #define DEFAULT_TCP_BLKSIZE (128 * 1024) default size 
    //printf("blfksize: %d\n", sp->settings->blksize);
    r = Nread(sp->socket, sp->buffer, sp->settings->blksize, Ptcp);

    //printf("client socket: %d\n", sp->socket);
    if (r < 0)
        return r;

    /* Only count bytes received while we're in the correct state. */
    if (sp->test->state == TEST_RUNNING) {
	sp->result->bytes_received += r;
	sp->result->bytes_received_this_interval += r;
    }
    else {
	if (sp->test->debug)
	    printf("Late receive, state = %d\n", sp->test->state);
    }

    return r;
}


void print_stack_trace() {
    // Size of the buffer to store the stack addresses
    const int max_frames = 128;
    void *buffer[max_frames];

    // Capture the backtrace
    int frame_count = backtrace(buffer, max_frames);

    // Translate the addresses into an array of strings
    char **symbols = backtrace_symbols(buffer, frame_count);
    if (symbols == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }

    // Print the stack trace
    printf("Stack trace:\n");
    for (int i = 0; i < frame_count; i++) {
        printf("%s\n", symbols[i]);
    }

    // Free the memory allocated for the symbols
    free(symbols);
}

/* iperf_tcp_send
 *
 * sends the data for TCP
 */
//Todo handles sent
int
iperf_tcp_send(struct iperf_stream *sp)
{
    //print_stack_trace();
    int r;

    if (!sp->pending_size)
	sp->pending_size = sp->settings->blksize;

    if (sp->test->zerocopy)
	r = Nsendfile(sp->buffer_fd, sp->socket, sp->buffer, sp->pending_size);
    else {
	r = Nwrite(sp->socket, sp->buffer, sp->pending_size, Ptcp);

	//printf("write packet size: %d\n", sp->pending_size);

    }
    if (r < 0)
        return r;

    sp->pending_size -= r;
    sp->result->bytes_sent += r;
    sp->result->bytes_sent_this_interval += r;

    if (sp->test->debug_level >=  DEBUG_LEVEL_DEBUG)
	printf("sent %d bytes of %d, pending %d, total %" PRIu64 "\n",
	    r, sp->settings->blksize, sp->pending_size, sp->result->bytes_sent);

    return r;
}

// Function to print the status of a socket option
void print_socket_option(int sockfd, int level, int optname, const char *optname_str) {
    int optval;
    socklen_t optlen = sizeof(optval);

    if (getsockopt(sockfd, level, optname, &optval, &optlen) == 0) {
        printf("%s: %s\n", optname_str, (optval ? "ON" : "OFF"));
    } else {
        perror(optname_str);
    }
}

/* iperf_tcp_accept
 *
 * accept a new TCP stream connection
 */
int
iperf_tcp_accept(struct iperf_test * test)
{
    int     s;
    signed char rbuf = ACCESS_DENIED;
    char    cookie[COOKIE_SIZE] = {0};
    socklen_t len;
    struct sockaddr_storage addr;

    len = sizeof(addr);

     // Array of socket options to check
    struct {
        int level;
        int optname;
        const char *optname_str;
    } socket_options[] = {
        {SOL_SOCKET, SO_DEBUG, "SO_DEBUG"},
        {SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR"},
        {SOL_SOCKET, SO_TYPE, "SO_TYPE"},
        {SOL_SOCKET, SO_ERROR, "SO_ERROR"},
        {SOL_SOCKET, SO_DONTROUTE, "SO_DONTROUTE"},
        {SOL_SOCKET, SO_BROADCAST, "SO_BROADCAST"},
        {SOL_SOCKET, SO_SNDBUF, "SO_SNDBUF"},
        {SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF"},
        {SOL_SOCKET, SO_KEEPALIVE, "SO_KEEPALIVE"},
        {SOL_SOCKET, SO_OOBINLINE, "SO_OOBINLINE"},
        {SOL_SOCKET, SO_LINGER, "SO_LINGER"},
        {SOL_SOCKET, SO_RCVLOWAT, "SO_RCVLOWAT"},
        {SOL_SOCKET, SO_SNDLOWAT, "SO_SNDLOWAT"},
        {SOL_SOCKET, SO_RCVTIMEO, "SO_RCVTIMEO"},
        {SOL_SOCKET, SO_SNDTIMEO, "SO_SNDTIMEO"},
        {SOL_SOCKET, SO_ACCEPTCONN, "SO_ACCEPTCONN"},
        {SOL_SOCKET, SO_REUSEPORT, "SO_REUSEPORT"},
        {SOL_SOCKET, SO_TIMESTAMP, "SO_TIMESTAMP"},
        {SOL_SOCKET, SO_BINDTODEVICE, "SO_BINDTODEVICE"},
        {IPPROTO_TCP, TCP_NODELAY, "TCP_NODELAY"},
        {IPPROTO_TCP, TCP_MAXSEG, "TCP_MAXSEG"},
        {IPPROTO_TCP, TCP_CORK, "TCP_CORK"},
        {IPPROTO_TCP, TCP_KEEPIDLE, "TCP_KEEPIDLE"},
        {IPPROTO_TCP, TCP_KEEPINTVL, "TCP_KEEPINTVL"},
        {IPPROTO_TCP, TCP_KEEPCNT, "TCP_KEEPCNT"},
        {IPPROTO_TCP, TCP_SYNCNT, "TCP_SYNCNT"},
        {IPPROTO_TCP, TCP_LINGER2, "TCP_LINGER2"},
        {IPPROTO_TCP, TCP_DEFER_ACCEPT, "TCP_DEFER_ACCEPT"},
        {IPPROTO_TCP, TCP_WINDOW_CLAMP, "TCP_WINDOW_CLAMP"},
        {IPPROTO_TCP, TCP_INFO, "TCP_INFO"},
        {IPPROTO_TCP, TCP_QUICKACK, "TCP_QUICKACK"}
    };

            // Number of socket options to check
    int num_options = sizeof(socket_options) / sizeof(socket_options[0]);

    // Print the status of each socket option
    for (int i = 0; i < num_options; i++) {
        print_socket_option(test->listener, socket_options[i].level, socket_options[i].optname, socket_options[i].optname_str);
    }

    if ((s = accept(test->listener, (struct sockaddr *) &addr, &len)) < 0) {
        i_errno = IESTREAMCONNECT;
        return -1;
    }

#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If fq socket pacing is specified, enable it. */

    if (test->settings->fqrate) {
	/* Convert bits per second to bytes per second */
	unsigned int fqrate = test->settings->fqrate / 8;
	if (fqrate > 0) {
	    if (test->debug) {
		printf("Setting fair-queue socket pacing to %u\n", fqrate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &fqrate, sizeof(fqrate)) < 0) {
		warning("Unable to set socket pacing");
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */

    if (Nread(s, cookie, COOKIE_SIZE, Ptcp) < 0) {
        i_errno = IERECVCOOKIE;
        close(s);
        return -1;
    }

    if (strncmp(test->cookie, cookie, COOKIE_SIZE) != 0) {
        if (Nwrite(s, (char*) &rbuf, sizeof(rbuf), Ptcp) < 0) {
            iperf_err(test, "failed to send access denied from busy server to new connecting client, errno = %d\n", errno);
        }
        close(s);
    }

    return s;
}


/* iperf_tcp_listen
 *
 * start up a listener for TCP stream connections
 */
int
iperf_tcp_listen(struct iperf_test *test)
{
    int s, opt;
    socklen_t optlen;
    int saved_errno;
    int rcvbuf_actual, sndbuf_actual;

    s = test->listener;

    /*
     * If certain parameters are specified (such as socket buffer
     * size), then throw away the listening socket (the one for which
     * we just accepted the control connection) and recreate it with
     * those parameters.  That way, when new data connections are
     * set, they'll have all the correct parameters in place.
     *
     * It's not clear whether this is a requirement or a convenience.
     */
    if (test->no_delay || test->settings->mss || test->settings->socket_bufsize) {
	struct addrinfo hints, *res;
	char portstr[6];

        FD_CLR(s, &test->read_set);
        close(s);

        snprintf(portstr, 6, "%d", test->server_port);
        memset(&hints, 0, sizeof(hints));

	/*
	 * If binding to the wildcard address with no explicit address
	 * family specified, then force us to get an AF_INET6 socket.
	 * More details in the comments in netanounce().
	 */
	if (test->settings->domain == AF_UNSPEC && !test->bind_address) {
	    hints.ai_family = AF_INET6;
	}
	else {
	    hints.ai_family = test->settings->domain;
	}
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        if ((gerror = getaddrinfo(test->bind_address, portstr, &hints, &res)) != 0) {
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        if ((s = socket(res->ai_family, SOCK_STREAM, 0)) < 0) {
	    freeaddrinfo(res);
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        if (test->no_delay) {
            opt = 1;
            if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETNODELAY;
                return -1;
            }
        }
        // XXX: Setting MSS is very buggy!
        if ((opt = test->settings->mss)) {
            if (setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETMSS;
                return -1;
            }
        }
        if ((opt = test->settings->socket_bufsize)) {
            if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETBUF;
                return -1;
            }
            if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETBUF;
                return -1;
            }
        }
    {
	unsigned int rate = test->settings->rate / 8;
	if (rate > 0) {
	    if (test->debug) {
		printf("Setting application pacing to %u\n", rate);
	    }
	}
    }
        opt = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
            close(s);
	    freeaddrinfo(res);
	    errno = saved_errno;
            i_errno = IEREUSEADDR;
            return -1;
        }

	/*
	 * If we got an IPv6 socket, figure out if it should accept IPv4
	 * connections as well.  See documentation in netannounce() for
	 * more details.
	 */
#if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC || test->settings->domain == AF_INET)) {
	    if (test->settings->domain == AF_UNSPEC)
		opt = 0;
	    else
		opt = 1;
	    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
			   (char *) &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
		i_errno = IEV6ONLY;
		return -1;
	    }
	}
#endif /* IPV6_V6ONLY */

        if (bind(s, (struct sockaddr *) res->ai_addr, res->ai_addrlen) < 0) {
	    saved_errno = errno;
            close(s);
	    freeaddrinfo(res);
	    errno = saved_errno;
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        freeaddrinfo(res);

        if (listen(s, INT_MAX) < 0) {
            i_errno = IESTREAMLISTEN;
            close(s);
            return -1;
        }

        test->listener = s;
    }

    /* Read back and verify the sender socket buffer size */
    optlen = sizeof(sndbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("SNDBUF is %u, expecting %u\n", sndbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > sndbuf_actual) {
	i_errno = IESETBUF2;
    close(s);
	return -1;
    }

    /* Read back and verify the receiver socket buffer size */
    optlen = sizeof(rcvbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("RCVBUF is %u, expecting %u\n", rcvbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > rcvbuf_actual) {
	i_errno = IESETBUF2;
    close(s);
	return -1;
    }

    if (test->json_output) {
	cJSON_AddNumberToObject(test->json_start, "sock_bufsize", test->settings->socket_bufsize);
	cJSON_AddNumberToObject(test->json_start, "sndbuf_actual", sndbuf_actual);
	cJSON_AddNumberToObject(test->json_start, "rcvbuf_actual", rcvbuf_actual);
    }

    return s;
}


/* iperf_tcp_connect
 *
 * connect to a TCP stream listener
 * This function is roughly similar to netdial(), and may indeed have
 * been derived from it at some point, but it sets many TCP-specific
 * options between socket creation and connection.
 */
int
iperf_tcp_connect(struct iperf_test *test)
{

    printf("iperf_tcp_connect\n");
    struct addrinfo *server_res;
    int s, opt;
    socklen_t optlen;
    int saved_errno;
    int rcvbuf_actual, sndbuf_actual;

    printf("connect bind-address: %s\n", test->server_hostname);
    s = create_socket(test->settings->domain, SOCK_STREAM, test->bind_address, test->bind_dev, test->bind_port, test->server_hostname, test->server_port, &server_res);
    if (s < 0) {
	i_errno = IESTREAMCONNECT;
	return -1;
    }

    /* Set socket options */
    if (test->no_delay) {
        opt = 1;
        if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETNODELAY;
            return -1;
        }
    }
    if ((opt = test->settings->mss)) {
        if (setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETMSS;
            return -1;
        }
    }
    if ((opt = test->settings->socket_bufsize)) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
    }
#if defined(HAVE_TCP_USER_TIMEOUT)
    if ((opt = test->settings->snd_timeout)) {
        if (setsockopt(s, IPPROTO_TCP, TCP_USER_TIMEOUT, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETUSERTIMEOUT;
            return -1;
        }
    }
#endif /* HAVE_TCP_USER_TIMEOUT */

    /* Read back and verify the sender socket buffer size */
    optlen = sizeof(sndbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("SNDBUF is %u, expecting %u\n", sndbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > sndbuf_actual) {
	i_errno = IESETBUF2;
	return -1;
    }

    /* Read back and verify the receiver socket buffer size */
    optlen = sizeof(rcvbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("RCVBUF is %u, expecting %u\n", rcvbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > rcvbuf_actual) {
	i_errno = IESETBUF2;
	return -1;
    }

    if (test->json_output) {
    cJSON *sock_bufsize_item = cJSON_GetObjectItem(test->json_start, "sock_bufsize");
    if (sock_bufsize_item == NULL) {
    cJSON_AddNumberToObject(test->json_start, "sock_bufsize", test->settings->socket_bufsize);
    }

    cJSON *sndbuf_actual_item = cJSON_GetObjectItem(test->json_start, "sndbuf_actual");
    if (sndbuf_actual_item == NULL) {
	cJSON_AddNumberToObject(test->json_start, "sndbuf_actual", sndbuf_actual);
    }
        
    cJSON *rcvbuf_actual_item = cJSON_GetObjectItem(test->json_start, "rcvbuf_actual");
    if (rcvbuf_actual_item == NULL) {
	cJSON_AddNumberToObject(test->json_start, "rcvbuf_actual", rcvbuf_actual);
    }
    }

#if defined(HAVE_FLOWLABEL)
    if (test->settings->flowlabel) {
        if (server_res->ai_addr->sa_family != AF_INET6) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETFLOW;
            return -1;
	} else {
	    struct sockaddr_in6* sa6P = (struct sockaddr_in6*) server_res->ai_addr;
            char freq_buf[sizeof(struct in6_flowlabel_req)];
            struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)freq_buf;
            int freq_len = sizeof(*freq);

            memset(freq, 0, sizeof(*freq));
            freq->flr_label = htonl(test->settings->flowlabel & IPV6_FLOWINFO_FLOWLABEL);
            freq->flr_action = IPV6_FL_A_GET;
            freq->flr_flags = IPV6_FL_F_CREATE;
            freq->flr_share = IPV6_FL_S_ANY;
            memcpy(&freq->flr_dst, &sa6P->sin6_addr, 16);

            if (setsockopt(s, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, freq_len) < 0) {
		saved_errno = errno;
                close(s);
                freeaddrinfo(server_res);
		errno = saved_errno;
                i_errno = IESETFLOW;
                return -1;
            }
            sa6P->sin6_flowinfo = freq->flr_label;

            opt = 1;
            if (setsockopt(s, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
                close(s);
                freeaddrinfo(server_res);
		errno = saved_errno;
                i_errno = IESETFLOW;
                return -1;
            }
	}
    }
#endif /* HAVE_FLOWLABEL */

#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If socket pacing is specified try to enable it. */
    if (test->settings->fqrate) {
	/* Convert bits per second to bytes per second */
	unsigned int fqrate = test->settings->fqrate / 8;
	if (fqrate > 0) {
	    if (test->debug) {
		printf("Setting fair-queue socket pacing to %u\n", fqrate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &fqrate, sizeof(fqrate)) < 0) {
		warning("Unable to set socket pacing");
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */
    {
	unsigned int rate = test->settings->rate / 8;
	if (rate > 0) {
	    if (test->debug) {
		printf("Setting application pacing to %u\n", rate);
	    }
	}
    }

    /* Set common socket options */
    iperf_common_sockopts(test, s);

    printf("before connect\n");
    if (connect(s, (struct sockaddr *) server_res->ai_addr, server_res->ai_addrlen) < 0 && errno != EINPROGRESS) {
	printf("connect error %d\n", errno);
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    printf("after connect\n");
    freeaddrinfo(server_res);

    /* Send cookie for verification */
    if (Nwrite(s, test->cookie, COOKIE_SIZE, Ptcp) < 0) {
	saved_errno = errno;
	close(s);
	errno = saved_errno;
        i_errno = IESENDCOOKIE;
        return -1;
    }

    return s;
}
