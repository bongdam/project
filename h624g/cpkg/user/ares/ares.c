
#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

/* configure ARES by resolv.conf */
#define CONFIG_RESOLV_CONF      0

/* configure ARES by environment variables */
#define CONFIG_ENVIRON_VAR      0

struct qquery {
    ares_callback callback;
    void *arg;
};

#ifdef ARES_DEBUG
#define aresLog(a)      do { \
                            if (ares_verbose) \
                                printf a; \
                        } while (0)
#else
#define aresLog(a)	do {} while (0)
#endif

/* ---------------- private function prototype ----------------------------- */
static void ares__close_sockets(struct server_state *server);
#if CONFIG_RESOLV_CONF
static int ares__read_line(FILE *fp, char **buf, int *bufsize);
#endif
static int name_length(const unsigned char *encoded, const unsigned char *abuf, int alen, int *enclen);
static int ares_expand_name(const unsigned char *encoded, const unsigned char *abuf, int alen, char **s, int *enclen);
#if N_REFERRED
static void ares_free_errmem(char *mem);
#endif
static void ares_free_string(char *str);
static int ares_mkquery(const char *name, int dnsclass, int type, unsigned short id, int rd, unsigned char **buf, int *buflen);
#ifdef SUPPORT_TCP
static void write_tcp_data(ares_channel channel, fd_set *write_fds, time_t now);
static void read_tcp_data(ares_channel channel, fd_set *read_fds, time_t now);
#endif
static void read_udp_packets(ares_channel channel, fd_set *read_fds, time_t now);
static void process_timeouts(ares_channel channel, time_t now);
static void process_answer(ares_channel channel, unsigned char *abuf, int alen, int whichserver, int tcp, int now);
static void handle_error(ares_channel channel, int whichserver, time_t now);
static void next_server(ares_channel channel, struct query *query, time_t now);
#ifdef SUPPORT_TCP
static int open_tcp_socket(ares_channel channel, struct server_state *server);
#endif
static int open_udp_socket(ares_channel channel, struct server_state *server);
static int same_questions(const unsigned char *qbuf, int qlen, const unsigned char *abuf, int alen);
static void end_query(ares_channel channel, struct query *query, int status, unsigned char *abuf, int alen);
static void qcallback(void *arg, int status, unsigned char *abuf, int alen);
static void ares_send(ares_channel channel, const unsigned char *qbuf, int qlen, ares_callback callback, void *arg);
static int init_by_options(ares_channel channel, struct ares_options *options, int optmask);
#if CONFIG_ENVIRON_VAR
static int init_by_environment(ares_channel channel);
#endif
static int init_by_defaults(ares_channel channel);
#if CONFIG_RESOLV_CONF
static int init_by_resolv_conf(ares_channel channel);
static int config_domain(ares_channel channel, char *str);
static int config_lookup(ares_channel channel, const char *str);
static int config_nameserver(struct server_state **servers, int *nservers, const char *str);
static int config_sortlist(struct apattern **sortlist, int *nsort, const char *str);
static char *try_config(char *s, char *opt);
static int ip_addr(const char *s, int len, struct in_addr *addr);
static void natural_mask(struct apattern *pat);
#endif
#if CONFIG_ENVIRON_VAR || CONFIG_RESOLV_CONF
static int set_search(ares_channel channel, const char *str);
static int set_options(ares_channel channel, const char *str);
static const char *try_option(const char *p, const char *q, const char *opt);
#endif
static void ares__send_query(ares_channel channel, struct query *query, time_t now);
#ifdef ARES_DEBUG
static const char *type_name(int type);
static const char *class_name(int dnsclass);
#endif

/* --------------- imported function prototype & variables ----------------- */
extern time_t sys_uptime(time_t *tm);

#ifdef ARES_DEBUG
int ares_verbose;
#endif

int ares_errno;

static void
ares__close_sockets(struct server_state *server)
{
#ifdef SUPPORT_TCP
    struct send_request *sendreq;

    /* Free all pending output buffers. */
    while (server->qhead) {
        /* Advance server->qhead; pull out query as we go. */

        sendreq = server->qhead;
        server->qhead = sendreq->next;
        free(sendreq);
    }
    server->qtail = NULL;

    /* Reset any existing input buffer. */
    if (server->tcp_buffer)
        free(server->tcp_buffer);
    server->tcp_buffer = NULL;
    server->tcp_lenbuf_pos = 0;

    /* Close the TCP and UDP sockets. */
    if (server->tcp_socket != -1) {
        CLOSE(server->tcp_socket);
        server->tcp_socket = -1;
    }
#endif
    if (server->udp_socket != -1) {
        CLOSE(server->udp_socket);
        server->udp_socket = -1;
    }
}

#if CONFIG_RESOLV_CONF
/* This is an internal function.  Its contract is to read a line from
 * a file into a dynamically allocated buffer, zeroing the trailing
 * newline if there is one.  The calling routine may call
 * ares__read_line multiple times with the same buf and bufsize
 * pointers; *buf will be REALLOCated and *bufsize adjusted as
 * appropriate.  The initial value of *buf should be NULL.  After the
 * calling routine is done reading lines, it should free *buf.
 */
static int
ares__read_line(FILE *fp, char **buf, int *bufsize)
{
    char *newbuf;
    int offset = 0, len;

    if (*buf == NULL) {
        *buf = malloc(128);
        if (!*buf)
            return ARES_ENOMEM;
        *bufsize = 128;
    }

    while (1) {
        if (!fgets(*buf + offset, *bufsize - offset, fp))
            return (offset != 0) ? 0 : (ferror(fp)) ? ARES_EFILE : ARES_EOF;
        len = offset + (int)strlen(*buf + offset);
        if ((*buf)[len - 1] == '\n') {
            (*buf)[len - 1] = 0;
            return ARES_SUCCESS;
        }
        offset = len;

        /* Allocate more space. */
        newbuf = realloc(*buf, *bufsize * 2);
        if (!newbuf)
            return ARES_ENOMEM;
        *buf = newbuf;
        *bufsize *= 2;
    }
}
#endif

void
ares_do_fini(ares_channel channel)
{
    int i;
    struct query *query;

    for (i = 0; i < channel->nservers; i++)
        ares__close_sockets(&channel->servers[i]);
    free(channel->servers);
    for (i = 0; i < channel->ndomains; i++)
        free(channel->domains[i]);
    free(channel->domains);
    free(channel->sortlist);
    free(channel->lookups);
    while (channel->queries) {
        query = channel->queries;
        channel->queries = query->next;
        query->callback(query->arg, ARES_EDESTRUCTION, NULL, 0);
        free(query->tcpbuf);
        free(query->skip_server);
        free(query);
    }
    free(channel);
}

/* Expand an RFC1035-encoded domain name given by encoded.  The
 * containing message is given by abuf and alen.  The result given by
 * *s, which is set to a NUL-terminated allocated buffer.  *enclen is
 * set to the length of the encoded name (not the length of the
 * expanded name; the goal is to tell the caller how many bytes to
 * move forward to get past the encoded name).
 *
 * In the simple case, an encoded name is a series of labels, each
 * composed of a one-byte length (limited to values between 0 and 63
 * inclusive) followed by the label contents.  The name is terminated
 * by a zero-length label.
 *
 * In the more complicated case, a label may be terminated by an
 * indirection pointer, specified by two bytes with the high bits of
 * the first byte (corresponding to INDIR_MASK) set to 11.  With the
 * two high bits of the first byte stripped off, the indirection
 * pointer gives an offset from the beginning of the containing
 * message with more labels to decode.  Indirection can happen an
 * arbitrary number of times, so we have to detect loops.
 *
 * Since the expanded name uses '.' as a label separator, we use
 * backslashes to escape periods or backslashes in the expanded name.
 */

static int
ares_expand_name(const unsigned char *encoded, const unsigned char *abuf, int alen, char **s, int *enclen)
{
    int len; /*indir = 0*/
    char *q;
    const unsigned char *p;

    len = name_length(encoded, abuf, alen, enclen);
    if (len == -1)
        return ARES_EBADNAME;

    if (s) {
        *s = malloc(len + 1);
        if (!*s)
            return ARES_ENOMEM;
        q = *s;

        /* No error-checking necessary; it was all done by name_length(). */
        p = encoded;
        while (*p) {
            if ((*p & INDIR_MASK) == INDIR_MASK) {
                /* if (!indir) {
                    *enclen = p + 2 - encoded;
                    indir = 1;
                } */
                p = abuf + ((*p & ~INDIR_MASK) << 8 | *(p + 1));
            } else {
                len = *p;
                p++;
                while (len--) {
                    if (*p == '.' || *p == '\\')
                        *q++ = '\\';
                    *q++ = *p;
                    p++;
                }
                *q++ = '.';
            }
        }
        /* if (!indir)
            *enclen = p + 1 - encoded; */

        /* Nuke the trailing period if we wrote one. */
        if (q > *s)
            *(q - 1) = 0;
    }
    return ARES_SUCCESS;
}

/* Return the length of the expansion of an encoded domain name, or
 * -1 if the encoding is invalid.
 */
static int
name_length(const unsigned char *encoded, const unsigned char *abuf, int alen, int *enclen)
{
    const unsigned char *p;
    int n = 0, offset, indir = 0;

    /* Allow the caller to pass us abuf + alen and have us check for it. */
    if (encoded == abuf + alen)
        return -1;

    p = encoded;
    while (*p) {
        if ((*p & INDIR_MASK) == INDIR_MASK) {
            /* Check the offset and go there. */
            if (p + 1 >= abuf + alen)
                return -1;
            offset = (*p & ~INDIR_MASK) << 8 | *(p + 1);
            if (offset >= alen)
                return -1;

            if (!indir)
                *enclen = p + 2 - encoded;

            p = abuf + offset;

            /* If we've seen more indirects than the message length,
             * then there's a loop.
             */
            if (++indir > alen)
                return -1;
        } else {
            offset = *p;
            if (p + offset + 1 >= abuf + alen)
                return -1;
            p++;
            while (offset--) {
                n += (*p == '.' || *p == '\\') ? 2 : 1;
                p++;
            }
            n++;
        }
    }

    if (!indir)
        *enclen = p + 1 - encoded;

    /* If there were any labels at all, then the number of dots is one
     * less than the number of labels, so subtract one.
     */
    return (n) ? n - 1 : n;
}

int
ares_do_fdset(ares_channel channel, fd_set *read_fds
#ifdef SUPPORT_TCP
              , fd_set *write_fds
#endif
              )
{
    struct server_state *server;
    int i, nfds;

    /* No queries, no file descriptors. */
    if (!channel->queries)
        return 0;

    nfds = -1;
    for (i = 0; i < channel->nservers; i++) {
        server = &channel->servers[i];
        if (server->udp_socket != -1) {
            FD_SET(server->udp_socket, read_fds);
            if (server->udp_socket > nfds)
                nfds = server->udp_socket;
        }
#ifdef SUPPORT_TCP
        if (server->tcp_socket != -1) {
            FD_SET(server->tcp_socket, read_fds);
            if (server->qhead)
                FD_SET(server->tcp_socket, write_fds);
            if (server->tcp_socket > nfds)
                nfds = server->tcp_socket;
        }
#endif
    }
    return nfds;
}

#if N_REFERRED
static void
ares_free_errmem(char *mem)
{
}
#endif

void
ares_free_areshost(struct ahostent *host)
{
    char **p;

    if (host == NULL)
        return;

    free(host->a_name);
    if (host->u.a_addr_list) {
        for (p = host->u.a_addr_list; *p; p++)
            free(*p);
        free(host->u.a_addr_list);
    }
    free(host);
}

static void ares_free_string(char *str)
{
    free(str);
}

/* Header format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * AA, TC, RA, and RCODE are only set in responses.  Brief description
 * of the remaining fields:
 *      ID      Identifier to match responses with queries
 *      QR      Query [0] or response [1]
 *      Opcode  For our purposes, always QUERY
 *      RD      Recursion desired
 *      Z       Reserved [zero]
 *      QDCOUNT Number of queries
 *      ANCOUNT Number of answers
 *      NSCOUNT Number of name server records
 *      ARCOUNT Number of additional records
 *
 * Question format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The query name is encoded as a series of labels, each represented
 * as a one-byte length (maximum 63) followed by the text of the
 * label.  The list is terminated by a label of length zero (which can
 * be thought of as the root domain).
 */
static int
ares_mkquery(const char *name, int dnsclass, int type, unsigned short id, int rd, unsigned char **buf, int *buflen)
{
    int len;
    unsigned char *q;
    const char *p;

    /* Compute the length of the encoded name so we can check buflen.
     * Start counting at 1 for the zero-length label at the end. */
    len = 1;
    for (p = name; *p; p++) {
        if (*p == '\\' && *(p + 1) != 0)
            p++;
        len++;
    }
    /* If there are n periods in the name, there are n + 1 labels, and
     * thus n + 1 length fields, unless the name is empty or ends with a
     * period.  So add 1 unless name is empty or ends with a period.
     */
    if (*name && *(p - 1) != '.')
        len++;

    *buflen = len + HFIXEDSZ + QFIXEDSZ;
    *buf = malloc(*buflen);
    if (!*buf)
        return ARES_ENOMEM;

    /* Set up the header. */
    q = *buf;
    memset(q, 0, HFIXEDSZ);
    DNS_HEADER_SET_QID(q, id);
    DNS_HEADER_SET_OPCODE(q, QUERY);
    DNS_HEADER_SET_RD(q, (rd) ? 1 : 0);
    DNS_HEADER_SET_QDCOUNT(q, 1);

    /* A name of "." is a screw case for the loop below, so adjust it. */
    if (strcmp(name, ".") == 0)
        name++;

    /* Start writing out the name after the header. */
    q += HFIXEDSZ;
    while (*name) {
        if (*name == '.')
            return ARES_EBADNAME;

        /* Count the number of bytes in this label. */
        len = 0;
        for (p = name; *p && *p != '.'; p++) {
            if (*p == '\\' && *(p + 1) != 0)
                p++;
            len++;
        }
        if (len > MAXLABEL)
            return ARES_EBADNAME;

        /* Encode the length and copy the data. */
        *q++ = len;
        for (p = name; *p && *p != '.'; p++) {
            if (*p == '\\' && *(p + 1) != 0)
                p++;
            *q++ = *p;
        }

        /* Go to the next label and repeat, unless we hit the end. */
        if (!*p)
            break;
        name = p + 1;
    }

    /* Add the zero-length label at the end. */
    *q++ = 0;

    /* Finish off the question with the type and class. */
    DNS_QUESTION_SET_TYPE(q, type);
    DNS_QUESTION_SET_CLASS(q, dnsclass);

    return ARES_SUCCESS;
}

void
ares_do_process(ares_channel channel, fd_set *read_fds
#ifdef SUPPORT_TCP
                , fd_set *write_fds
#endif
                )
{
    time_t now;

    sys_uptime(&now);
#ifdef SUPPORT_TCP
    write_tcp_data(channel, write_fds, now);
    read_tcp_data(channel, read_fds, now);
#endif
    read_udp_packets(channel, read_fds, now);
    process_timeouts(channel, now);
}

#ifdef SUPPORT_TCP
/* If any TCP sockets select true for writing, write out queued data
 * we have for them.
 */
static void
write_tcp_data(ares_channel channel, fd_set *write_fds, time_t now)
{
    struct server_state *server;
    struct send_request *sendreq;
    struct iovec *vec;
    int i, n, count;

    for (i = 0; i < channel->nservers; i++) {
        /* Make sure server has data to send and is selected in write_fds. */
        server = &channel->servers[i];
        if (!server->qhead || server->tcp_socket == -1
                || !FD_ISSET(server->tcp_socket, write_fds))
            continue;

        /* Count the number of send queue items. */
        n = 0;
        for (sendreq = server->qhead; sendreq; sendreq = sendreq->next)
            n++;

        /* Allocate iovecs so we can send all our data at once. */
        vec = malloc(n * sizeof(struct iovec));
        if (vec) {
            /* Fill in the iovecs and send. */
            n = 0;
            for (sendreq = server->qhead; sendreq; sendreq = sendreq->next) {
                vec[n].iov_base = (char *) sendreq->data;
                vec[n].iov_len = sendreq->len;
                n++;
            }
            count = writev(server->tcp_socket, vec, n);
            free(vec);
            if (count < 0) {
                handle_error(channel, i, now);
                continue;
            }

            /* Advance the send queue by as many bytes as we sent. */
            while (count) {
                sendreq = server->qhead;
                if (count >= sendreq->len) {
                    count -= sendreq->len;
                    server->qhead = sendreq->next;
                    if (server->qhead == NULL)
                        server->qtail = NULL;
                    free(sendreq);
                } else {
                    sendreq->data += count;
                    sendreq->len -= count;
                    break;
                }
            }
        } else {
            /* Can't allocate iovecs; just send the first request. */
            sendreq = server->qhead;
            count = write(server->tcp_socket, sendreq->data, sendreq->len);
            if (count < 0) {
                handle_error(channel, i, now);
                continue;
            }

            /* Advance the send queue by as many bytes as we sent. */
            if (count == sendreq->len) {
                server->qhead = sendreq->next;
                if (server->qhead == NULL)
                    server->qtail = NULL;
                free(sendreq);
            } else {
                sendreq->data += count;
                sendreq->len -= count;
            }
        }
    }
}

/* If any TCP socket selects true for reading, read some data,
 * allocate a buffer if we finish reading the length word, and process
 * a packet if we finish reading one.
 */
static void
read_tcp_data(ares_channel channel, fd_set *read_fds, time_t now)
{
    struct server_state *server;
    int i, count;

    for (i = 0; i < channel->nservers; i++) {
        /* Make sure the server has a socket and is selected in read_fds. */
        server = &channel->servers[i];
        if (server->tcp_socket == -1 || !FD_ISSET(server->tcp_socket, read_fds))
            continue;

        if (server->tcp_lenbuf_pos != 2) {
            /* We haven't yet read a length word, so read that (or
             * what's left to read of it).
             */
            count = read(server->tcp_socket,
                         server->tcp_lenbuf + server->tcp_lenbuf_pos,
                         2 - server->tcp_lenbuf_pos);
            if (count <= 0) {
                handle_error(channel, i, now);
                continue;
            }

            server->tcp_lenbuf_pos += count;
            if (server->tcp_lenbuf_pos == 2) {
                /* We finished reading the length word.  Decode the
                     * length and allocate a buffer for the data.
                 */
                server->tcp_length = server->tcp_lenbuf[0] << 8
                                     | server->tcp_lenbuf[1];
                server->tcp_buffer = malloc(server->tcp_length);
                if (!server->tcp_buffer)
                    handle_error(channel, i, now);
                server->tcp_buffer_pos = 0;
            }
        } else {
            /* Read data into the allocated buffer. */
            count = read(server->tcp_socket,
                         server->tcp_buffer + server->tcp_buffer_pos,
                         server->tcp_length - server->tcp_buffer_pos);
            if (count <= 0) {
                handle_error(channel, i, now);
                continue;
            }

            server->tcp_buffer_pos += count;
            if (server->tcp_buffer_pos == server->tcp_length) {
                /* We finished reading this answer; process it and
                     * prepare to read another length word.
                 */
                process_answer(channel, server->tcp_buffer, server->tcp_length,
                               i, 1, now);
                free(server->tcp_buffer);
                server->tcp_buffer = NULL;
                server->tcp_lenbuf_pos = 0;
            }
        }
    }
}
#endif

/* If any UDP sockets select true for reading, process them. */
static void
read_udp_packets(ares_channel channel, fd_set *read_fds,
                             time_t now)
{
    struct server_state *server;
    int i, count;
    unsigned char buf[PACKETSZ + 1];

    for (i = 0; i < channel->nservers; i++) {
        /* Make sure the server has a socket and is selected in read_fds. */
        server = &channel->servers[i];
        if (server->udp_socket == -1 || !FD_ISSET(server->udp_socket, read_fds))
            continue;

        count = recv(server->udp_socket, buf, sizeof(buf), 0);
        if (count <= 0)
            handle_error(channel, i, now);

        process_answer(channel, buf, count, i, 0, now);
    }
}

/* If any queries have timed out, note the timeout and move them on. */
static void
process_timeouts(ares_channel channel, time_t now)
{
    struct query *query, *next;

    for (query = channel->queries; query; query = next) {
        next = query->next;
        if (query->timeout != 0 && now >= query->timeout) {
            query->error_status = ARES_ETIMEOUT;
            next_server(channel, query, now);
        }
    }
}

/* Handle an answer from a server. */
static void
process_answer(ares_channel channel, unsigned char *abuf, int alen, int whichserver, int tcp, int now)
{
    int id, rcode;
    struct query *query;
#ifdef SUPPORT_TCP
    int tc;
#endif
    /* If there's no room in the answer for a header, we can't do much
     * with it. */
    if (alen < HFIXEDSZ)
        return;

    /* Grab the query ID, truncate bit, and response code from the packet. */
    id = DNS_HEADER_QID(abuf);
#ifdef SUPPORT_TCP
    tc = DNS_HEADER_TC(abuf);
#endif
    rcode = DNS_HEADER_RCODE(abuf);

    /* Find the query corresponding to this packet. */
    for (query = channel->queries; query; query = query->next) {
        if (query->qid == id)
            break;
    }
    if (!query)
        return;
#ifdef SUPPORT_TCP
    /* If we got a truncated UDP packet and are not ignoring truncation,
     * don't accept the packet, and switch the query to TCP if we hadn't
     * done so already.
     */
    if ((tc || alen > PACKETSZ) && !tcp && !(channel->flags & ARES_FLAG_IGNTC)) {
        if (!query->using_tcp) {
            query->using_tcp = 1;
            ares__send_query(channel, query, now);
        }
        return;
    }
#endif
    /* Limit alen to PACKETSZ if we aren't using TCP (only relevant if we
     * are ignoring truncation.
     */
    if (alen > PACKETSZ
#ifdef SUPPORT_TCP
            && !tcp
#endif
       )
        alen = PACKETSZ;

    /* If we aren't passing through all error packets, discard packets
     * with SERVFAIL, NOTIMP, or REFUSED response codes.
     */
    if (!(channel->flags & ARES_FLAG_NOCHECKRESP)) {
        if (rcode == SERVFAIL || rcode == NOTIMP || rcode == REFUSED) {
            query->skip_server[whichserver] = 1;
            if (query->server == whichserver)
                next_server(channel, query, now);
            return;
        }
        if (!same_questions((unsigned char *)query->qbuf, query->qlen, abuf, alen)) {
            if (query->server == whichserver)
                next_server(channel, query, now);
            return;
        }
    }

    end_query(channel, query, ARES_SUCCESS, abuf, alen);
}

static void
handle_error(ares_channel channel, int whichserver, time_t now)
{
    struct query *query ,*next;

    /* Reset communications with this server. */
    ares__close_sockets(&channel->servers[whichserver]);

    /* Tell all queries talking to this server to move on and not try
     * this server again.
     */
    for (query = channel->queries; query; query = next) {
        next = query->next;
        if (query->server == whichserver) {
            query->skip_server[whichserver] = 1;
            next_server(channel, query, now);
        }
    }
}

static void
next_server(ares_channel channel, struct query *query, time_t now)
{
    /* Advance to the next server or try. */
    query->server++;
    for (; query->try < channel->tries; query->try++) {
        for (; query->server < channel->nservers; query->server++) {
            if (!query->skip_server[query->server]) {
                ares__send_query(channel, query, now);
                return;
            }
        }
        query->server = 0;
#ifdef SUPPORT_TCP
        /* Only one try if we're using TCP. */
        if (query->using_tcp)
            break;
#endif
    }
    end_query(channel, query, query->error_status, NULL, 0);
}

static void
ares__send_query(ares_channel channel, struct query *query, time_t now)
{
#ifdef SUPPORT_TCP
    struct send_request *sendreq;
#endif
    struct server_state *server;

    server = &channel->servers[query->server];
#ifdef SUPPORT_TCP
    if (query->using_tcp) {
        /* Make sure the TCP socket for this server is set up and queue
         * a send request.
         */
        if (server->tcp_socket == -1) {
            if (open_tcp_socket(channel, server) == -1) {
                query->skip_server[query->server] = 1;
                next_server(channel, query, now);
                return;
            }
        }
        sendreq = malloc(sizeof(struct send_request));
        if (!sendreq)
            end_query(channel, query, ARES_ENOMEM, NULL, 0);
        sendreq->data = query->tcpbuf;
        sendreq->len = query->tcplen;
        sendreq->next = NULL;
        if (server->qtail)
            server->qtail->next = sendreq;
        else
            server->qhead = sendreq;
        server->qtail = sendreq;
        query->timeout = 0;
    } else
#endif
    {
        if (server->udp_socket == -1) {
            if (open_udp_socket(channel, server) == -1) {
                query->skip_server[query->server] = 1;
                next_server(channel, query, now);
                return;
            }
        }
        if (send(server->udp_socket, query->qbuf, query->qlen, 0) == -1) {
            query->skip_server[query->server] = 1;
            next_server(channel, query, now);
            return;
        }

        query->timeout = now
                         + ((query->try == 0) ? channel->timeout
                            : channel->timeout << query->try / channel->nservers);
    }
}

#ifdef SUPPORT_TCP
static int
open_tcp_socket(ares_channel channel, struct server_state *server)
{
    int s, flags;
    struct sockaddr_in sin;

    /* Acquire a socket. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1)
        return -1;
#ifdef WIN32
    flags = 1;  /* 0 for blocking / 1 for non-blocking */
    if (ioctlsocket(s, FIONBIO, (u_long *)&flags) == -1) {
        fprintf(stderr, "ERR: so_initopt: ioctlsocket: set non-blocking failed: %s\n", so_strerror(so_errno));
        goto error;
    }
#else
    /* Set the socket non-blocking. */
    if (fcntl(s, F_GETFL, &flags) == -1) {
        CLOSE(s);
        return -1;
    }
    flags &= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) == -1) {
        CLOSE(s);
        return -1;
    }
#endif
    /* Connect to the server. */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = server->addr;
    sin.sin_port = channel->tcp_port;
    if (connect(s, (struct sockaddr *) &sin, sizeof(sin)) == -1
            && errno != EINPROGRESS) {
        CLOSE(s);
        return -1;
    }

    server->tcp_socket = s;
    return 0;
}
#endif

static int
open_udp_socket(ares_channel channel, struct server_state *server)
{
    int s;
    struct sockaddr_in sin;

    /* Acquire a socket. */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
        return -1;

    /* Connect to the server. */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = server->addr;
    sin.sin_port = channel->udp_port;
    if (connect(s, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        CLOSE(s);
        return -1;
    }

    server->udp_socket = s;
    return 0;
}

static int
same_questions(const unsigned char *qbuf, int qlen, const unsigned char *abuf, int alen)
{
    struct {
        const unsigned char *p;
        int qdcount;
        char *name;
        int namelen;
        int type;
        int dnsclass;
    } q, a;
    int i, j;

    if (qlen < HFIXEDSZ || alen < HFIXEDSZ)
        return 0;

    /* Extract qdcount from the request and reply buffers and compare them. */
    q.qdcount = DNS_HEADER_QDCOUNT(qbuf);
    a.qdcount = DNS_HEADER_QDCOUNT(abuf);
    if (q.qdcount != a.qdcount)
        return 0;

    /* For each question in qbuf, find it in abuf. */
    q.p = qbuf + HFIXEDSZ;
    for (i = 0; i < q.qdcount; i++) {
        /* Decode the question in the query. */
        if (ares_expand_name(q.p, qbuf, qlen, &q.name, &q.namelen)
                != ARES_SUCCESS)
            return 0;
        q.p += q.namelen;
        if (q.p + QFIXEDSZ > qbuf + qlen) {
            free(q.name);
            return 0;
        }
        q.type = DNS_QUESTION_TYPE(q.p);
        q.dnsclass = DNS_QUESTION_CLASS(q.p);
        q.p += QFIXEDSZ;

        /* Search for this question in the answer. */
        a.p = abuf + HFIXEDSZ;
        for (j = 0; j < a.qdcount; j++) {
            /* Decode the question in the answer. */
            if (ares_expand_name(a.p, abuf, alen, &a.name, &a.namelen)
                    != ARES_SUCCESS) {
                free(q.name);
                return 0;
            }
            a.p += a.namelen;
            if (a.p + QFIXEDSZ > abuf + alen) {
                free(q.name);
                free(a.name);
                return 0;
            }
            a.type = DNS_QUESTION_TYPE(a.p);
            a.dnsclass = DNS_QUESTION_CLASS(a.p);
            a.p += QFIXEDSZ;

            /* Compare the decoded questions. */
            if (strcasecmp(q.name, a.name) == 0 && q.type == a.type
                    && q.dnsclass == a.dnsclass) {
                free(a.name);
                break;
            }
            free(a.name);
        }

        free(q.name);
        if (j == a.qdcount)
            return 0;
    }
    return 1;
}

static void
end_query(ares_channel channel, struct query *query, int status, unsigned char *abuf, int alen)
{
    struct query **q;
    int i;

    for (q = &channel->queries; *q; q = &(*q)->next) {
        if (*q == query)
            break;
    }
    *q = query->next;
    /* after removing from the chain of query, make call to callback function
     * which enables for callback function to schedule an another query.
     * 12mar09 young
     */
    query->callback(query->arg, status, abuf, alen);

    free(query->tcpbuf);
    free(query->skip_server);
    free(query);

    /* Simple cleanup policy: if no queries are remaining, close all
     * network sockets unless STAYOPEN is set.
     */
    if (!channel->queries && !(channel->flags & ARES_FLAG_STAYOPEN)) {
        for (i = 0; i < channel->nservers; i++)
            ares__close_sockets(&channel->servers[i]);
    }
}

int
ares_do_query(ares_channel channel, const char *name, int dnsclass, int type, ares_callback callback, void *arg)
{
    struct ahostent *host = NULL;
    struct qquery *qquery;
    unsigned char *qbuf;
    int qlen, rd, status;

    host = (struct ahostent *)malloc(sizeof(struct ahostent));
    if (host == NULL)
        return -ARES_ENOMEM;

    host->a_priv = arg;
    host->a_name = strdup(name);
    host->a_recordtype = type;
    host->u.a_addr_list = 0;

    /* Compose the query. */
    rd = !(channel->flags & ARES_FLAG_NORECURSE);
    status = ares_mkquery(name, dnsclass, type, channel->next_id, rd, &qbuf,
                          &qlen);
    channel->next_id++;
    if (status != ARES_SUCCESS)
        return -status;

    /* Allocate and fill in the query structure. */
    qquery = malloc(sizeof(struct qquery));
    if (!qquery) {
        ares_free_string((char *)qbuf);
        return -ARES_ENOMEM;
    }
    qquery->callback = callback;
    qquery->arg = (void *)host;

    /* Send it off.  qcallback will be called when we get an answer. */
    ares_send(channel, qbuf, qlen, qcallback, qquery);
    ares_free_string((char *)qbuf);
    return 0;
}

static void
qcallback(void *arg, int status, unsigned char *abuf, int alen)
{
    struct qquery *qquery = (struct qquery *) arg;
    unsigned int ancount;
    int rcode;

    if (status != ARES_SUCCESS)
        qquery->callback(qquery->arg, status, abuf, alen);
    else {
        /* Pull the response code and answer count from the packet. */
        rcode = DNS_HEADER_RCODE(abuf);
        ancount = DNS_HEADER_ANCOUNT(abuf);

        /* Convert errors. */
        switch (rcode) {
        case NOERROR:
            status = (ancount > 0) ? ARES_SUCCESS : ARES_ENODATA;
            break;
        case FORMERR:
            status = ARES_EFORMERR;
            break;
        case SERVFAIL:
            status = ARES_ESERVFAIL;
            break;
        case NXDOMAIN:
            status = ARES_ENOTFOUND;
            break;
        case NOTIMP:
            status = ARES_ENOTIMP;
            break;
        case REFUSED:
            status = ARES_EREFUSED;
            break;
        }
        qquery->callback(qquery->arg, status, abuf, alen);
    }
    free(qquery);
}

static void
ares_send(ares_channel channel, const unsigned char *qbuf, int qlen, ares_callback callback, void *arg)
{
    struct query *query;
    int i;
    time_t now;

    /* Verify that the query is at least long enough to hold the header. */
    if (qlen < HFIXEDSZ || qlen >= (1 << 16)) {
        callback(arg, ARES_EBADQUERY, NULL, 0);
        return;
    }

    /* Allocate space for query and allocated fields. */
    query = malloc(sizeof(struct query));
    if (!query) {
        callback(arg, ARES_ENOMEM, NULL, 0);
        return;
    }

    query->tcpbuf = malloc(qlen + 2);
    if (!query->tcpbuf) {
        free(query);
        callback(arg, ARES_ENOMEM, NULL, 0);
        return;
    }

    query->skip_server = malloc(channel->nservers * sizeof(int));
    if (!query->skip_server) {
        free(query->tcpbuf);
        free(query);
        callback(arg, ARES_ENOMEM, NULL, 0);
        return;
    }

    /* Compute the query ID.  Start with no timeout. */
    query->qid = DNS_HEADER_QID(qbuf);
    query->timeout = 0;

    /* Form the TCP query buffer by prepending qlen (as two
     * network-order bytes) to qbuf.
     */
    query->tcpbuf[0] = (qlen >> 8) & 0xff;
    query->tcpbuf[1] = qlen & 0xff;
    memcpy(query->tcpbuf + 2, qbuf, qlen);
    query->tcplen = qlen + 2;

    /* Fill in query arguments. */
    query->qbuf = query->tcpbuf + 2;
    query->qlen = qlen;
    query->callback = callback;
    query->arg = arg;

    /* Initialize query status. */
    query->try = 0;
    query->server = 0;
    for (i = 0; i < channel->nservers; i++)
        query->skip_server[i] = 0;
#ifdef SUPPORT_TCP
    query->using_tcp = (channel->flags & ARES_FLAG_USEVC) || qlen > PACKETSZ;
#endif
    query->error_status = ARES_ECONNREFUSED;

    /* Chain the query into this channel's query list. */
    query->next = channel->queries;
    channel->queries = query;

    /* Perform the first query action. */
    sys_uptime(&now);
    ares__send_query(channel, query, now);
}

const char *
ares_strerror(int code)
{
    /* A future implementation may want to handle internationalization.
     * For now, just return a string literal from a table.
     */
    const char *errtext[] = {
        "Successful completion",
        "DNS server returned answer with no data",
        "DNS server claims query was misformatted",
        "DNS server returned general failure",
        "Domain name not found",
        "DNS server does not implement requested operation",
        "DNS server refused query",
        "Misformatted DNS query",
        "Misformatted domain name",
        "Unsupported address family",
        "Misformatted DNS reply",
        "Could not contact DNS servers",
        "Timeout while contacting DNS servers",
        "End of file",
        "Error reading file",
        "Out of memory",
        "Destruct query"
    };
    if (code >= 0 && code < (sizeof(errtext) / sizeof(*errtext)))
        return errtext[code];
    else
        return "Unkown error";
}

struct timeval *
ares_do_timeout(ares_channel channel, struct timeval *maxtv, struct timeval *tvbuf)
{
    struct query *query;
    time_t now;
    int offset, min_offset;

    /* No queries, no timeout (and no fetch of the current time). */
    if (!channel->queries)
        return maxtv;

    /* Find the minimum timeout for the current set of queries. */
    sys_uptime(&now);
    min_offset = -1;
    for (query = channel->queries; query; query = query->next) {
        if (query->timeout == 0)
            continue;
        offset = query->timeout - now;
        if (offset < 0)
            offset = 0;
        if (min_offset == -1 || offset < min_offset)
            min_offset = offset;
    }

    /* If we found a minimum timeout and it's sooner than the one
     * specified in maxtv (if any), return it.  Otherwise go with
     * maxtv.
     */
    if (min_offset != -1 && (!maxtv || min_offset <= maxtv->tv_sec)) {
        tvbuf->tv_sec = min_offset;
        tvbuf->tv_usec = 0;
        return tvbuf;
    } else
        return maxtv;
}

int ares_do_init(ares_channel *channelptr, struct ares_options *options, int optmask)
{
    ares_channel channel;
    int i, status;
    struct server_state *server;
    struct timeval tv;

    channel = malloc(sizeof(struct ares_channeldata));
    if (!channel)
        return ARES_ENOMEM;

    /* Set everything to distinguished values so we know they haven't
     * been set yet.
     */
    channel->flags = -1;
    channel->timeout = -1;
    channel->tries = -1;
    channel->ndots = -1;
    channel->udp_port = -1;
#ifdef SUPPORT_TCP
    channel->tcp_port = -1;
#endif
    channel->nservers = -1;
    channel->ndomains = -1;
    channel->nsort = -1;
    channel->lookups = NULL;

    /* Initialize configuration by each of the four sources, from highest
     * precedence to lowest.
     */
    status = init_by_options(channel, options, optmask);
#if CONFIG_ENVIRON_VAR
    if (status == ARES_SUCCESS)
        status = init_by_environment(channel);
#endif
#if CONFIG_RESOLV_CONF
    if (status == ARES_SUCCESS)
        status = init_by_resolv_conf(channel);
#endif
    if (status == ARES_SUCCESS)
        status = init_by_defaults(channel);
    if (status != ARES_SUCCESS) {
        /* Something failed; clean up memory we may have allocated. */
        if (channel->nservers != -1)
            free(channel->servers);
        if (channel->ndomains != -1) {
            for (i = 0; i < channel->ndomains; i++)
                free(channel->domains[i]);
            free(channel->domains);
        }
        if (channel->nsort != -1)
            free(channel->sortlist);
        free(channel->lookups);
        free(channel);
        return status;
    }

    /* Trim to one server if ARES_FLAG_PRIMARY is set. */
    if ((channel->flags & ARES_FLAG_PRIMARY) && channel->nservers > 1)
        channel->nservers = 1;

    /* Initialize server states. */
    for (i = 0; i < channel->nservers; i++) {
        server = &channel->servers[i];
        server->udp_socket = -1;
#ifdef SUPPORT_TCP
        server->tcp_socket = -1;
        server->tcp_lenbuf_pos = 0;
        server->tcp_buffer = NULL;
        server->qhead = NULL;
        server->qtail = NULL;
#endif
    }

    /* Choose a somewhat random query ID.  The main point is to avoid
     * collisions with stale queries.  An attacker trying to spoof a DNS
     * answer also has to guess the query ID, but it's only a 16-bit
     * field, so there's not much to be done about that.
     */
    gettimeofday(&tv, NULL);
    channel->next_id = (short)(tv.tv_sec ^ tv.tv_usec ^ getpid()) & 0xffff;

    channel->queries = NULL;

    *channelptr = channel;
    return ARES_SUCCESS;
}

static int
init_by_options(ares_channel channel, struct ares_options *options,
                           int optmask)
{
    int i;

    /* Easy stuff. */
    if ((optmask & ARES_OPT_FLAGS) && channel->flags == -1)
        channel->flags = options->flags;
    if ((optmask & ARES_OPT_TIMEOUT) && channel->timeout == -1)
        channel->timeout = options->timeout;
    if ((optmask & ARES_OPT_TRIES) && channel->tries == -1)
        channel->tries = options->tries;
    if ((optmask & ARES_OPT_NDOTS) && channel->ndots == -1)
        channel->ndots = options->ndots;
    if ((optmask & ARES_OPT_UDP_PORT) && channel->udp_port == -1)
        channel->udp_port = options->udp_port;
#ifdef SUPPORT_TCP
    if ((optmask & ARES_OPT_TCP_PORT) && channel->tcp_port == -1)
        channel->tcp_port = options->tcp_port;
#endif
    /* Copy the servers, if given. */
    if ((optmask & ARES_OPT_SERVERS) && channel->nservers == -1) {
        channel->servers =
            malloc(options->nservers * sizeof(struct server_state));
        if (!channel->servers && options->nservers != 0)
            return ARES_ENOMEM;
        for (i = 0; i < options->nservers; i++)
            channel->servers[i].addr = options->servers[i];
        channel->nservers = options->nservers;
    }

    /* Copy the domains, if given.  Keep channel->ndomains consistent so
     * we can clean up in case of error.
     */
    if ((optmask & ARES_OPT_DOMAINS) && channel->ndomains == -1) {
        channel->domains = malloc(options->ndomains * sizeof(char *));
        if (!channel->domains && options->ndomains != 0)
            return ARES_ENOMEM;
        for (i = 0; i < options->ndomains; i++) {
            channel->ndomains = i;
            channel->domains[i] = strdup(options->domains[i]);
            if (!channel->domains[i])
                return ARES_ENOMEM;
        }
        channel->ndomains = options->ndomains;
    }

    /* Set lookups, if given. */
    if ((optmask & ARES_OPT_LOOKUPS) && !channel->lookups) {
        channel->lookups = strdup(options->lookups);
        if (!channel->lookups)
            return ARES_ENOMEM;
    }

    return ARES_SUCCESS;
}

#if CONFIG_ENVIRON_VAR || CONFIG_RESOLV_CONF
static const char *
try_option(const char *p, const char *q, const char *opt)
{
    int len;

    len = strlen(opt);
    return (q - p > len && strncmp(p, opt, len) == 0) ? p + len : NULL;
}

static int
set_search(ares_channel channel, const char *str)
{
    int n;
    const char *p, *q;

    /* Count the domains given. */
    n = 0;
    p = str;
    while (*p) {
        while (*p && !isspace((unsigned char)*p))
            p++;
        while (isspace((unsigned char)*p))
            p++;
        n++;
    }

    channel->domains = malloc(n * sizeof(char *));
    if (!channel->domains && n)
        return ARES_ENOMEM;

    /* Now copy the domains. */
    n = 0;
    p = str;
    while (*p) {
        channel->ndomains = n;
        q = p;
        while (*q && !isspace((unsigned char)*q))
            q++;
        channel->domains[n] = malloc(q - p + 1);
        if (!channel->domains[n])
            return ARES_ENOMEM;
        memcpy(channel->domains[n], p, q - p);
        channel->domains[n][q - p] = 0;
        p = q;
        while (isspace((unsigned char)*p))
            p++;
        n++;
    }
    channel->ndomains = n;

    return ARES_SUCCESS;
}

static int
set_options(ares_channel channel, const char *str)
{
    const char *p, *q, *val;

    p = str;
    while (*p) {
        q = p;
        while (*q && !isspace((unsigned char)*q))
            q++;
        val = try_option(p, q, "ndots:");
        if (val && channel->ndots == -1)
            channel->ndots = atoi(val);
        val = try_option(p, q, "retrans:");
        if (val && channel->timeout == -1)
            channel->timeout = atoi(val);
        val = try_option(p, q, "retry:");
        if (val && channel->tries == -1)
            channel->tries = atoi(val);
        p = q;
        while (isspace((unsigned char)*p))
            p++;
    }

    return ARES_SUCCESS;
}
#endif

#if CONFIG_ENVIRON_VAR
static int
init_by_environment(ares_channel channel)
{
    const char *localdomain, *res_options;
    int status;

    localdomain = getenv("LOCALDOMAIN");
    if (localdomain && channel->ndomains == -1) {
        status = set_search(channel, localdomain);
        if (status != ARES_SUCCESS)
            return status;
    }

    res_options = getenv("RES_OPTIONS");
    if (res_options) {
        status = set_options(channel, res_options);
        if (status != ARES_SUCCESS)
            return status;
    }

    return ARES_SUCCESS;
}
#endif

static int
init_by_defaults(ares_channel channel)
{
    char hostname[MAXHOSTNAMELEN + 1];

    if (channel->flags == -1)
        channel->flags = 0;
    if (channel->timeout == -1)
        channel->timeout = DEFAULT_TIMEOUT;
    if (channel->tries == -1)
        channel->tries = DEFAULT_TRIES;
    if (channel->ndots == -1)
        channel->ndots = 1;
    if (channel->udp_port == -1)
        channel->udp_port = htons(NAMESERVER_PORT);
#ifdef SUPPORT_TCP
    if (channel->tcp_port == -1)
        channel->tcp_port = htons(NAMESERVER_PORT);
#endif
    if (channel->nservers == -1) {
        /* If nobody specified servers, try a local named. */
        channel->servers = malloc(sizeof(struct server_state));
        if (!channel->servers)
            return ARES_ENOMEM;
        channel->servers[0].addr.s_addr = htonl(INADDR_LOOPBACK);
        channel->nservers = 1;
    }

    if (channel->ndomains == -1) {
        /* Derive a default domain search list from the kernel hostname,
         * or set it to empty if the hostname isn't helpful.
         */
        if (gethostname(hostname, sizeof(hostname)) == -1
                || !strchr(hostname, '.')) {
            channel->domains = malloc(0);
            channel->ndomains = 0;
        } else {
            channel->domains = malloc(sizeof(char *));
            if (!channel->domains)
                return ARES_ENOMEM;
            channel->ndomains = 0;
            channel->domains[0] = strdup(strchr(hostname, '.') + 1);
            if (!channel->domains[0])
                return ARES_ENOMEM;
            channel->ndomains = 1;
        }
    }

    if (channel->nsort == -1) {
        channel->sortlist = NULL;
        channel->nsort = 0;
    }

    if (!channel->lookups) {
        channel->lookups = strdup("bf");
        if (!channel->lookups)
            return ARES_ENOMEM;
    }

    return ARES_SUCCESS;
}

#if CONFIG_RESOLV_CONF
static int
config_domain(ares_channel channel, char *str)
{
    char *q;

    /* Set a single search domain. */
    q = str;
    while (*q && !isspace((unsigned char)*q))
        q++;
    *q = 0;
    return set_search(channel, str);
}

static int
config_lookup(ares_channel channel, const char *str)
{
    char lookups[3], *l;
    const char *p;

    /* Set the lookup order.  Only the first letter of each work
     * is relevant, and it has to be "b" for DNS or "f" for the
     * host file.  Ignore everything else.
     */
    l = lookups;
    p = str;
    while (*p) {
        if ((*p == 'b' || *p == 'f') && l < lookups + 2)
            *l++ = *p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        while (isspace((unsigned char)*p))
            p++;
    }
    *l = 0;
    channel->lookups = strdup(lookups);
    return (channel->lookups) ? ARES_SUCCESS : ARES_ENOMEM;
}

static int
config_nameserver(struct server_state **servers, int *nservers, const char *str)
{
    struct in_addr addr;
    struct server_state *newserv;

    /* Add a nameserver entry, if this is a valid address. */
    addr.s_addr = inet_addr(str);
    if (addr.s_addr == INADDR_NONE)
        return ARES_SUCCESS;
    newserv = realloc(*servers, (*nservers + 1) * sizeof(struct server_state));
    if (!newserv)
        return ARES_ENOMEM;
    newserv[*nservers].addr = addr;
    *servers = newserv;
    (*nservers)++;
    return ARES_SUCCESS;
}

static int
config_sortlist(struct apattern **sortlist, int *nsort, const char *str)
{
    struct apattern pat, *newsort;
    const char *q;

    /* Add sortlist entries. */
    while (*str && *str != ';') {
        q = str;
        while (*q && *q != '/' && *q != ';' && !isspace((unsigned char)*q))
            q++;
        if (ip_addr(str, q - str, &pat.addr) == 0) {
            /* We have a pattern address; now determine the mask. */
            if (*q == '/') {
                str = q + 1;
                while (*q && *q != ';' && !isspace((unsigned char)*q))
                    q++;
                if (ip_addr(str, q - str, &pat.mask) != 0)
                    natural_mask(&pat);
            } else
                natural_mask(&pat);

            /* Add this pattern to our list. */
            newsort = realloc(*sortlist, (*nsort + 1) * sizeof(struct apattern));
            if (!newsort)
                return ARES_ENOMEM;
            newsort[*nsort] = pat;
            *sortlist = newsort;
            (*nsort)++;
        } else {
            while (*q && *q != ';' && !isspace((unsigned char)*q))
                q++;
        }
        str = q;
        while (isspace((unsigned char)*str))
            str++;
    }

    return ARES_SUCCESS;
}

static char *
try_config(char *s, char *opt)
{
    int len;

    len = strlen(opt);
    if (strncmp(s, opt, len) != 0 || !isspace((unsigned char)s[len]))
        return NULL;
    s += len;
    while (isspace((unsigned char)*s))
        s++;
    return s;
}

static int
ip_addr(const char *s, int len, struct in_addr *addr)
{
    char ipbuf[16];

    /* Four octets and three periods yields at most 15 characters. */
    if (len > 15)
        return -1;
    memcpy(ipbuf, s, len);
    ipbuf[len] = 0;

    addr->s_addr = inet_addr(ipbuf);
    if (addr->s_addr == INADDR_NONE && strcmp(ipbuf, "255.255.255.255") != 0)
        return -1;
    return 0;
}

static void
natural_mask(struct apattern *pat)
{
    struct in_addr addr;

    /* Store a host-byte-order copy of pat in a struct in_addr.  Icky,
     * but portable.
     */
    addr.s_addr = ntohl(pat->addr.s_addr);

    /* This is out of date in the CIDR world, but some people might
     * still rely on it.
     */
    if (IN_CLASSA(addr.s_addr))
        pat->mask.s_addr = htonl(IN_CLASSA_NET);
    else if (IN_CLASSB(addr.s_addr))
        pat->mask.s_addr = htonl(IN_CLASSB_NET);
    else
        pat->mask.s_addr = htonl(IN_CLASSC_NET);
}

static int
init_by_resolv_conf(ares_channel channel)
{
    FILE *fp;
    char *line = NULL, *p;
    int linesize, status, nservers = 0, nsort = 0;
    struct server_state *servers = NULL;
    struct apattern *sortlist = NULL;

    fp = fopen(PATH_RESOLV_CONF, "r");
    if (!fp)
        return (errno == ENOENT) ? ARES_SUCCESS : ARES_EFILE;
    while ((status = ares__read_line(fp, &line, &linesize)) == ARES_SUCCESS) {
        if ((p = try_config(line, "domain")) && channel->ndomains == -1)
            status = config_domain(channel, p);
        else if ((p = try_config(line, "lookup")) && !channel->lookups)
            status = config_lookup(channel, p);
        else if ((p = try_config(line, "search")) && channel->ndomains == -1)
            status = set_search(channel, p);
        else if ((p = try_config(line, "nameserver")) && channel->nservers == -1)
            status = config_nameserver(&servers, &nservers, p);
        else if ((p = try_config(line, "sortlist")) && channel->nsort == -1)
            status = config_sortlist(&sortlist, &nsort, p);
        else if ((p = try_config(line, "options")))
            status = set_options(channel, p);
        else
            status = ARES_SUCCESS;
        if (status != ARES_SUCCESS)
            break;
    }
    free(line);
    fclose(fp);

    /* Handle errors. */
    if (status != ARES_EOF) {
        free(servers);
        free(sortlist);
        return status;
    }

    /* If we got any name server entries, fill them in. */
    if (servers) {
        channel->servers = servers;
        channel->nservers = nservers;
    }

    /* If we got any sortlist entries, fill them in. */
    if (sortlist) {
        channel->sortlist = sortlist;
        channel->nsort = nsort;
    }

    return ARES_SUCCESS;
}
#endif

#ifdef ARES_DEBUG
const struct nv dns_flags[] = {
    { "usevc",          ARES_FLAG_USEVC },
    { "primary",                ARES_FLAG_PRIMARY },
    { "igntc",          ARES_FLAG_IGNTC },
    { "norecurse",      ARES_FLAG_NORECURSE },
    { "stayopen",               ARES_FLAG_STAYOPEN },
    { "noaliases",      ARES_FLAG_NOALIASES },
    { NULL, -1 }
};

const struct nv dns_classes[] = {
    { "IN",     C_IN },
    { "CHAOS",  C_CHAOS },
    { "HS",     C_HS },
    { "ANY",    C_ANY },
    { NULL, -1 }
};

const struct nv dns_types[] = {
    { "A",      T_A },
    { "NS",     T_NS },
    { "MD",     T_MD },
    { "MF",     T_MF },
    { "CNAME",  T_CNAME },
    { "SOA",    T_SOA },
    { "MB",     T_MB },
    { "MG",     T_MG },
    { "MR",     T_MR },
    { "NULL",   T_NULL },
    { "WKS",    T_WKS },
    { "PTR",    T_PTR },
    { "HINFO",  T_HINFO },
    { "MINFO",  T_MINFO },
    { "MX",     T_MX },
    { "TXT",    T_TXT },
    { "RP",     T_RP },
    { "AFSDB",  T_AFSDB },
    { "X25",    T_X25 },
    { "ISDN",   T_ISDN },
    { "RT",     T_RT },
    { "NSAP",   T_NSAP },
    { "NSAP_PTR",       T_NSAP_PTR },
    { "SIG",    T_SIG },
    { "KEY",    T_KEY },
    { "PX",     T_PX },
    { "GPOS",   T_GPOS },
    { "AAAA",   T_AAAA },
    { "LOC",    T_LOC },
    { "SRV",    T_SRV },
    { "AXFR",   T_AXFR },
    { "MAILB",  T_MAILB },
    { "MAILA",  T_MAILA },
    { "ANY",    T_ANY },
    { NULL, -1 }
};

static const char *opcodes[] = {
    "QUERY", "IQUERY", "STATUS", "(reserved)", "NOTIFY",
    "(unknown)", "(unknown)", "(unknown)", "(unknown)",
    "UPDATEA", "UPDATED", "UPDATEDA", "UPDATEM", "UPDATEMA",
    "ZONEINIT", "ZONEREF"
};

static const char *rcodes[] = {
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
    "(unknown)", "(unknown)", "(unknown)", "(unknown)", "(unknown)",
    "(unknown)", "(unknown)", "(unknown)", "(unknown)", "NOCHANGE"
};
#endif

static const unsigned char *
parse_question(const unsigned char *aptr, const unsigned char *abuf, int alen)
{
    char *name;
    int status, len;
#ifdef ARES_DEBUG
    int type, dnsclass;
#endif
    /* Parse the question name. */
    status = ares_expand_name(aptr, abuf, alen, &name, &len);
    if (status != ARES_SUCCESS)
        return NULL;
    aptr += len;

    /* Make sure there's enough data after the name for the fixed part
     * of the question.
     */
    if (aptr + QFIXEDSZ > abuf + alen) {
        free(name);
        return NULL;
    }
#ifdef ARES_DEBUG
    /* Parse the question type and class. */
    type = DNS_QUESTION_TYPE(aptr);
    dnsclass = DNS_QUESTION_CLASS(aptr);

    /* Display the question, in a format sort of similar to how we will
     * display RRs.
     */
    aresLog(("  %s: type %s, class %s\n", name, type_name(type), class_name(dnsclass)));
#endif
    aptr += QFIXEDSZ;
    free(name);
    return aptr;
}

static const unsigned char *
parse_rr(const unsigned char *aptr, const unsigned char *abuf, int alen, struct ahostent *host)
{
    const unsigned char *p;
    char *name;
#ifdef ARES_DEBUG
    int dnsclass;
#endif
    int type, ttl, dlen, status, len, i;
    struct in_addr addr;

    /* Parse the RR name. */
    status = ares_expand_name(aptr, abuf, alen, &name, &len);
    if (status != ARES_SUCCESS)
        return NULL;
    aptr += len;

    /* Make sure there is enough data after the RR name for the fixed
     * part of the RR.
     */
    if (aptr + RRFIXEDSZ > abuf + alen) {
        free(name);
        return NULL;
    }

    /* Parse the fixed part of the RR, and advance to the RR data
     * field. */
    type = DNS_RR_TYPE(aptr);
#ifdef ARES_DEBUG
    dnsclass = DNS_RR_CLASS(aptr);
#endif
    ttl = DNS_RR_TTL(aptr);
    dlen = DNS_RR_LEN(aptr);
    aptr += RRFIXEDSZ;
    if (aptr + dlen > abuf + alen) {
        free(name);
        return NULL;
    }

    /* Display the RR name, class, and type. */
    aresLog(("  %s: type %s, class %s", name, type_name(type), class_name(dnsclass)));
    free(name);

    /* Display the RR data.  Don't touch aptr. */
    switch (type) {
    case T_CNAME:
    case T_MB:
    case T_MD:
    case T_MF:
    case T_MG:
    case T_MR:
    case T_NS:
    case T_PTR:
        /* For these types, the RR data is just a domain name. */
        status = ares_expand_name(aptr, abuf, alen, &name, &len);
        if (status != ARES_SUCCESS)
            return NULL;

        aresLog((" %s.", name));
        free(name);
        break;

    case T_HINFO:
        /* The RR data is two length-counted character strings. */
        p = aptr;
        len = *p;
        if (p + len + 1 > aptr + dlen)
            return NULL;
        aresLog((" %.*s", len, p + 1));
        p += len + 1;
        len = *p;
        if (p + len + 1 > aptr + dlen)
            return NULL;
        aresLog((" %.*s", len, p + 1));
        break;

    case T_MINFO:
        /* The RR data is two domain names. */
        p = aptr;
        status = ares_expand_name(p, abuf, alen, &name, &len);
        if (status != ARES_SUCCESS)
            return NULL;
        aresLog((" %s.", name));
        free(name);
        p += len;
        status = ares_expand_name(p, abuf, alen, &name, &len);
        if (status != ARES_SUCCESS)
            return NULL;
        aresLog((" %s.", name));
        free(name);
        break;

    case T_MX:
        /* The RR data is two bytes giving a preference ordering, and
         * then a domain name.
         */
        if (dlen < 2)
            return NULL;
        aresLog(("  %d", (aptr[0] << 8) | aptr[1]));
        status = ares_expand_name(aptr + 2, abuf, alen, &name, &len);
        if (status != ARES_SUCCESS)
            return NULL;
        aresLog(("  %s.", name));
        free(name);
        break;

    case T_SOA:
        /* The RR data is two domain names and then five four-byte
         * numbers giving the serial number and some timeouts.
         */
        p = aptr;
        status = ares_expand_name(p, abuf, alen, &name, &len);
        if (status != ARES_SUCCESS)
            return NULL;
        aresLog((" %s.\n", name));
        free(name);
        p += len;
        status = ares_expand_name(p, abuf, alen, &name, &len);
        if (status != ARES_SUCCESS)
            return NULL;
        aresLog(("\t%s.\n", name));
        free(name);
        p += len;
        if (p + 20 > aptr + dlen)
            return NULL;

        aresLog(("\t( %d %d %d %d %d )",
                   (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3],
                   (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7],
                   (p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11],
                   (p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15],
                   (p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]));
        break;

    case T_TXT:
        /* The RR data is one or more length-counted character
         * strings. */
        p = aptr;
        while (p < aptr + dlen) {
            len = *p;
            if (p + len + 1 > aptr + dlen)
                return NULL;
            aresLog((" %.*s", len, p + 1));
            p += len + 1;
        }
        break;

    case T_A:
        /* The RR data is a four-byte Internet address. */
        if (dlen != 4)
            return NULL;

        if (host != NULL) {
            for (i = 0; host->u.a_addr_list[i]; i++)
                ;
            host->u.a_addr_list[i] = (char *)malloc(sizeof(struct in_addr));
            if (host->u.a_addr_list[i])
                memcpy(host->u.a_addr_list[i], aptr, sizeof(struct in_addr));
        }

        memcpy(&addr, aptr, sizeof(struct in_addr));
        aresLog((" %s", inet_ntoa(addr)));
        break;

    case T_WKS:
        /* Not implemented yet */
        break;

    case T_SRV:
        /* The RR data is three two-byte numbers representing the
         * priority, weight, and port, followed by a domain name.
         */
    {
        struct srv_addr *sa = NULL;

        sa = (struct srv_addr *)malloc(sizeof(struct srv_addr));
        if (sa == NULL)
            return NULL;

        sa->s_ttl = ttl;
        sa->s_priority = DNS__16BIT(aptr);
        sa->s_weight = DNS__16BIT(aptr + 2);
        sa->s_port = DNS__16BIT(aptr + 4);

        status = ares_expand_name(aptr + 6, abuf, alen, &name, &len);
        if (status != ARES_SUCCESS) {
            free(sa);
            return NULL;
        }

        if (host != NULL) {
            for (i = 0; host->u.a_addr_list[i]; i++)
                ;
            host->u.a_addr_list[i] = (char *)sa;
            strncpy(sa->s_target, name, sizeof(sa->s_target) - 1);
            sa->s_target[sizeof(sa->s_target) - 1] = 0;
        }

        aresLog(("\n\t%d %d %d  %s.", sa->s_priority, sa->s_weight, sa->s_port, sa->s_target));

        if (host == NULL)
            free(sa);
        free(name);
    }
        break;

    default:
        aresLog(("  [Unknown RR; cannot parse]"));
    }
    aresLog(("\n"));

    return aptr + dlen;
}

int
ares_host_parse(void *arg, int status, unsigned char *abuf, int alen)
{
    struct ahostent * host = (struct ahostent *)arg;
    int i;
#ifdef ARES_DEBUG
    int qr, opcode, aa, tc, rd, ra, rcode;
#endif
    int qdcount, ancount, nscount, arcount;
    const unsigned char *aptr;

    if (host == NULL || host->a_name == NULL || host->a_name[0] == '\0')
        return -1;

    /* Display an error message if there was an error, but only stop if
     * we actually didn't get an answer buffer.
     */
    if (status != ARES_SUCCESS)
        if (!abuf)
            return -1;

    /* Won't happen, but check anyway, for safety. */
    if (alen < HFIXEDSZ)
        return -1;
#ifdef ARES_DEBUG
    /* Parse the answer header. */
    qr = DNS_HEADER_QR(abuf);
    opcode = DNS_HEADER_OPCODE(abuf);
    aa = DNS_HEADER_AA(abuf);
    tc = DNS_HEADER_TC(abuf);
    rd = DNS_HEADER_RD(abuf);
    ra = DNS_HEADER_RA(abuf);
    rcode = DNS_HEADER_RCODE(abuf);

    aresLog(("transaction: 0x%04x\n", (int)(unsigned short)DNS_HEADER_QID(abuf)));
    aresLog(("flags: 0x%04x\n", (int)(unsigned short)DNS__16BIT(abuf + 2)));
    aresLog(("  %d... .... .... .... = %s\n", qr, (qr) ? "response" : "query"));
    aresLog(("  .%d%d%d %d... .... .... = opcode: %s\n",
                (opcode >> 3) & 1, (opcode >> 2) & 1, (opcode >> 1) & 1, opcode & 1, opcodes[opcode]));
    aresLog(("  .... .%d.. .... .... = %s\n", aa, (aa) ? "authoritative" : "not authoritative"));
    aresLog(("  .... ..%d. .... .... = %s\n", tc, (tc) ? "truncated" : "not truncated"));
    aresLog(("  .... ...%d .... .... = recursion %s\n", rd, (rd) ? "desired" : "not desired"));
    aresLog(("  .... .... %d... .... = recursion %s\n", ra, (ra) ? "available" : "unavailable"));
    aresLog(("  .... .... .... %d%d%d%d = reply code: %s\n",
                (rcode >> 3) & 1, (rcode >> 2) & 1, (rcode >> 1) & 1, rcode & 1, rcodes[rcode]));
#endif
    qdcount = DNS_HEADER_QDCOUNT(abuf);
    ancount = DNS_HEADER_ANCOUNT(abuf);
    nscount = DNS_HEADER_NSCOUNT(abuf);
    arcount = DNS_HEADER_ARCOUNT(abuf);

    host->u.a_addr_list = (char **)malloc(sizeof(char *) * (ancount + 1));
    if (host->u.a_addr_list == NULL)
        return -1;
    memset(host->u.a_addr_list, 0, sizeof(char *) * (ancount + 1));

    aptr = abuf + HFIXEDSZ;

    aresLog(("Queries:\n"));
    for (i = 0; i < qdcount; i++) {
        aptr = parse_question(aptr, abuf, alen);
        if (aptr == NULL)
            return -1;
    }

    aresLog(("Answers:\n"));
    for (i = 0; i < ancount; i++) {
        aptr = parse_rr(aptr, abuf, alen, host);
        if (aptr == NULL)
            return -1;
    }

    aresLog(("Authoritative nameservers:\n"));
    for (i = 0; i < nscount; i++) {
        aptr = parse_rr(aptr, abuf, alen, NULL);
        if (aptr == NULL)
            return -1;
    }

    aresLog(("Additional records:\n"));
    for (i = 0; i < arcount; i++) {
        aptr = parse_rr(aptr, abuf, alen, NULL);
        if (aptr == NULL)
            return -1;
    }

    return 0;
}

#ifdef ARES_DEBUG
static const char *
type_name(int type)
{
    int i;

    for (i = 0; dns_types[i].name; i++) {
        if (dns_types[i].value == type)
            return dns_types[i].name;
    }
    return "(unknown)";
}

static const char *
class_name(int dnsclass)
{
    int i;

    for (i = 0; dns_classes[i].name != 0; i++) {
        if (dns_classes[i].value == dnsclass)
            return dns_classes[i].name;
    }
    return "(unknown)";
}
#endif

/* ----------------------------------------------------------------------------
 * Operating System Specific Wrapper
 * ----------------------------------------------------------------------------
 */
#ifdef WIN32
int gettimeofday(struct timeval *tp, void *tzp)
{
    struct _timeb timebuffer;

    _ftime(&timebuffer);
    tp->tv_sec = timebuffer.time;
    tp->tv_usec = timebuffer.millitm * 1000;
    return 0;
}
#endif

time_t sys_uptime(time_t *tm)
{
#ifdef WIN32
    return time(tm);
#else
    struct sysinfo info;

    sysinfo(&info);
    if (tm)
        *tm = info.uptime;
    return (time_t)info.uptime;
#endif
}
