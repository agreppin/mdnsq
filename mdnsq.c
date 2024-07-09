/*
 * Copyright (c) 2024, Alain Greppin
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* https://en.wikipedia.org/wiki/Multicast_DNS */
/* https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef DEBUG
#define DEBUG 0
#endif
#if !DEBUG
#define perror(x) do {} while (0)
#endif

typedef const uint8_t *cdata_t;

enum constants_ {
  DNS_PACKET_HEADER_SIZE = 12,
  MAX_LABEL_LENGTH = 255,
  MAX_UDP_MUL_OUT = 9000,
  MAX_UDP_MUL_IN = 16384,
  MAX_OFFSETS = MAX_UDP_MUL_IN / 4,
};

/* https://en.wikipedia.org/wiki/List_of_DNS_record_types */
typedef enum qtype_ {
  RTYPE_A     = 1,
  RTYPE_PTR   = 12,
  RTYPE_TXT   = 16,
  RTYPE_AAAA  = 28,
  RTYPE_SRV   = 33,
  RTYPE_ANY   = 255,
} qtype_t;

typedef union sockaddr_ {
  struct sockaddr s;
  struct sockaddr_in s4;
  struct sockaddr_in6 s6;
} sockaddr_t;

typedef struct query_ {
	size_t raw_size;
	uint8_t raw_data[MAX_UDP_MUL_OUT];
  uint16_t vo[MAX_OFFSETS]; /* valid offsets */
} query_t;

/* Resource Record */
typedef struct rr_ {
  cdata_t rrname;       /* owner raw data */
  uint16_t rrtype;
  uint16_t rrclass_;    /* cache_flush 1 bit, rrclass 15 bits */
  uint16_t lbls;        /* rdata.name labels count */
  uint32_t ttl;
  uint16_t rdlen;
  cdata_t rraw;  /* A, AAAA, PTR, SRV, ... rdlen bytes */
} rr_t;

typedef struct response_ {
  cdata_t msg;
  ssize_t size;
  uint16_t vo[MAX_OFFSETS]; /* valid offsets */
  uint16_t id;
  uint16_t flags;
  uint16_t questions;
  uint16_t answer_rr;
  uint16_t authority_rr;
  uint16_t additional_rr;
  rr_t *rr;
} response_t;

typedef struct mdnsq_ {
  sockaddr_t sa;
  int dbg;
  int ipv6;
  int sock;
  struct timeval tmout;
  const char *qname;
  qtype_t qtype;
  query_t q;
  uint32_t qnums;
  uint32_t qreqs[256];
} mdnsq_t;

#define NELEMS(x) (sizeof(x) / sizeof(x[0]))

#if !(FUZZ+0) /* _debug_hexdump */
static const char _hex[16] = "0123456789abcdef";

static inline void xwrite(int fd, const void *buf, size_t n) {
  n = write(fd, buf, n);
}

static void _debug_hexdump(cdata_t buf, ssize_t size) {
  const int lines = ((size + 15) >> 4);
  if (size > 0) {
    char out[lines * 72], *p = out;
    for (int n = 0; n < lines; ++n, buf += 16, size -= 16) {
      int i, len = (size < 16) ? size : 16;
      for (i = 0, *p++ = ' '; i < len; ++i)
        *p++ = ' ', *p++ = _hex[buf[i] >> 4], *p++ = _hex[buf[i] & 0xf];
      for (/**/; i < 16; ++i)
        *p++ = ' ', *p++ = ' ', *p++ = ' ';
      for (i = 0, *p++ = ' ', *p++ = '|'; i < len; ++i)
        *p++ = (buf[i] >= 0x20 && buf[i] < 0x7f) ? buf[i] : '.';
      *p++ = '|', *p++ = '\n';
    }
    xwrite(2, out, p - out);
  }
}
#endif

static cdata_t mdnsq_read_ntohs(cdata_t p, uint16_t *v) {
  *v = ntohs(*(uint16_t *)p);
  return p + 2;
}

static cdata_t mdnsq_read_ntohl(cdata_t p, uint32_t *v) {
  *v = ntohl(*(uint32_t *)p);
  return p + 4;
}

static int mdnsq_out_htons(query_t *q, uint16_t v) {
  uint8_t *p = q->raw_data + q->raw_size;
  if (q->raw_size >= MAX_UDP_MUL_OUT - 2)
    return -1;
  *(uint16_t *)p = htons(v);
  q->raw_size += 2;
  return 0;
}

/* https://datatracker.ietf.org/doc/html/rfc6762#section-18.1
 * In multicast query messages, the Query Identifier SHOULD be set to
 * zero on transmission. */
static query_t *mdnsq_new_query(mdnsq_t *s) {
	query_t *q = &s->q;
  q->raw_size = 0;
  mdnsq_out_htons(q, 0); /* id */
  mdnsq_out_htons(q, 0); /* flags */
  mdnsq_out_htons(q, 0); /* questions */
  mdnsq_out_htons(q, 0); /* Answers RRs */
  mdnsq_out_htons(q, 0); /* Authority RRs */
  mdnsq_out_htons(q, 0); /* Additional RRs */
  memset(q->vo, 0, sizeof(q->vo));
	return q;
}

/* assuming RR@p is valid */
static cdata_t mdnsq_count_labels(cdata_t p, uint16_t *nlbls, cdata_t msg) {
  for (uint16_t n; /**/; /**/) {
    n = *p;
    if ((n & 0xc0) == 0xc0) {
      p = mdnsq_read_ntohs(p, &n);
      n &= 0x3fff;
      mdnsq_count_labels(msg + n, nlbls, msg);
      return p;
    }

    p += n + 1;
    if (n > 0)
      ++(*nlbls);
    else
      return p;
  }
}

#if !(FUZZ+0)
static int mdnsq_udp_write(mdnsq_t *s, cdata_t buf, int bufsize) {
  socklen_t addrlen = s->ipv6 ? sizeof(s->sa.s6) : sizeof(s->sa.s4);
  int ret = sendto(s->sock, buf, bufsize, 0, &s->sa.s, addrlen);
  if (s->dbg > 0) {
    xwrite(2, "SEND:\n", 6);
    _debug_hexdump(buf, bufsize);
  }
  if (ret < 0)
    perror("sendto");
  return ret;
}

static void mdnsq_adjust_timeout(mdnsq_t *s) {
  struct timeval *tv = &s->tmout;
  const int wait_min_usec = 150 * 1000;
  if (!tv->tv_sec && tv->tv_usec < wait_min_usec)
    tv->tv_usec = wait_min_usec;
}
#endif

static cdata_t _offset_skip(cdata_t ptr, cdata_t msg) {
  uint16_t n = *ptr;
  if ((n & 0xc0) == 0xc0) {
    n = ntohs(*(uint16_t *)ptr);
    n &= 0x3fff; /* offset */
    ptr = msg + n;
  }
  return ptr;
}

static uint16_t _offset_find(const query_t *q, cdata_t respmsg, cdata_t rraw) {
  cdata_t const qend = q->raw_data + q->raw_size;
  const uint16_t *vo = q->vo;
  for (int i = 0; i < MAX_OFFSETS && vo[i]; ++i) {
    cdata_t qptr = q->raw_data + vo[i];
    cdata_t rptr = rraw;
    for (uint16_t n; qptr < qend; /**/) {
      qptr = _offset_skip(qptr, q->raw_data);
      rptr = _offset_skip(rptr, respmsg);
      if ((n = *qptr++) != *rptr++)
        break;
      if (n == 0)
        return vo[i];
      for (uint16_t j = 0; j < n; ++j)
        if (*qptr++ != *rptr++)
          goto next_offset;
    }
next_offset:
    continue;
  }
  return 0;
}

static void _offset_save(uint16_t vo[], long offset) {
  for (int i = 0; i < MAX_OFFSETS; ++i) {
    if (vo[i] == 0)
      vo[i] = offset;
    if (vo[i] == offset)
      break;
  }
}

/* with labels compression / offsets */
static int mdnsq_add_labels(query_t *q, cdata_t respmsg, cdata_t rraw) {
  uint8_t *p = q->raw_data + q->raw_size;
  uint16_t n;

  for (;;) {
    n = *rraw;
    if ((n & 0xc0) == 0xc0) {
      n = ntohs(*(uint16_t *)rraw);
      n &= 0x3fff; /* offset */
      return mdnsq_add_labels(q, respmsg, respmsg + n);
    } else {
      uint8_t *const s = p;
      uint16_t o = _offset_find(q, respmsg, rraw);
      if (o)
        return mdnsq_out_htons(q, 0xc000 | o);
      ++rraw;
      *p++ = n;
      for (uint16_t i = 0; i < n; ++i)
        *p++ = *rraw++;
      q->raw_size += n + 1;
      if (n == 0)
        return 0;
      _offset_save(q->vo, s - q->raw_data);
    }
  }
}

static int mdnsq_packet_addq(query_t *q, cdata_t respmsg, cdata_t rraw, uint16_t rrtype) {
  const size_t saved_size = q->raw_size;
  if (!mdnsq_add_labels(q, respmsg, rraw) &&
    !mdnsq_out_htons(q, rrtype) &&
    !mdnsq_out_htons(q, 0x0001)) { /* QU=0 + QCLASS=1 */
    /* success: increment questions */
    uint16_t *questions = (uint16_t *)(q->raw_data + 4);
    *questions = htons(ntohs(*questions) + 1);
    return 0;
  }
  /* rollback */
  q->raw_size = saved_size;
  return -1;
}

static uint32_t hash_name(cdata_t rptr, cdata_t msg) {
  for (uint32_t h = 5381, n; /**/; /**/) {
    rptr = _offset_skip(rptr, msg);
    if ((n = *rptr) == 0)
      return h;
    for (uint32_t i = 0; i <= n; ++i)
      h = ((h << 5) + h) ^ *rptr++;
  }
}

static int query_sent(mdnsq_t *s, uint32_t h) {
  for (uint32_t i = 0; i < s->qnums && i < NELEMS(s->qreqs); ++i)
    if (h == s->qreqs[i])
      return 1;
  return 0;
}

#if !(FUZZ+0)
static inline char _as_printable(uint8_t c) {
  return c; // c < 0x1b ? 0xb7 : c; // TODO maybe
}

static char *_add_rraw(char *p, cdata_t rraw, cdata_t msg) {
  cdata_t rptr = rraw;
  for (unsigned n; /**/; /**/) {
    rptr = _offset_skip(rptr, msg);
    n = *rptr++;
    if (n == 0)
      return p;
    for (unsigned i = 0; i < n; ++i)
      *p++ = _as_printable(*rptr++);
    *p++ = '.';
  }
}

static char *_add_str(char *p, const char *s) {
  while (*s)
    *p++ = *s++;
  return p;
}
#endif

static int cb_response(mdnsq_t *s, const response_t *r, unsigned nmax) {
  query_t *q = NULL;
  int ret = 0;

  for (unsigned i = r->questions; i < nmax; ++i) {
    const rr_t *rr = &r->rr[i];
    qtype_t rrtype = rr->rrtype;
    uint32_t h;
    switch (rrtype) {
    case RTYPE_PTR:
      if (rr->lbls != 3)
        break;
      h = hash_name(rr->rraw, r->msg);
      if (query_sent(s, h))
        break;
      if (q == NULL)
        q = mdnsq_new_query(s);
      mdnsq_packet_addq(q, r->msg, rr->rraw, rr->rrtype);
      if (s->qnums < NELEMS(s->qreqs))
        s->qreqs[s->qnums++] = h;
      break;
    default:
      break;
    }
  }
#if !(FUZZ+0)
  if (q != NULL) {
    mdnsq_adjust_timeout(s);
    ret = mdnsq_udp_write(s, q->raw_data, q->raw_size);
  }

  /* now output info */
  char buf[MAX_UDP_MUL_IN], *p = buf;
  for (unsigned i = r->questions; i < nmax; ++i) {
    const rr_t *rr = &r->rr[i];
    qtype_t rrtype = rr->rrtype;
    switch (rrtype) {
    case RTYPE_A:
      p = _add_str(p, "   A: ");
      break;
    case RTYPE_AAAA:
      p = _add_str(p, "AAAA: ");
      break;
    case RTYPE_PTR:
      p = _add_str(p, " PTR: ");
      break;
    case RTYPE_SRV:
      p = _add_str(p, " SRV: ");
    default:
      break;
    }
    switch (rrtype) {
    case RTYPE_A:
    case RTYPE_AAAA:
    case RTYPE_PTR:
    case RTYPE_SRV:
      p = _add_rraw(p, rr->rrname, r->msg);
      p = _add_str(p, " (");
    default:
      break;
    }
    switch (rrtype) {
    case RTYPE_A:
      if (inet_ntop(AF_INET, rr->rraw, p, INET_ADDRSTRLEN))
        p = _add_str(p, p);
      break;
    case RTYPE_AAAA:
      if (inet_ntop(AF_INET6, rr->rraw, p, INET6_ADDRSTRLEN))
        p = _add_str(p, p);
      break;
    case RTYPE_PTR:
    case RTYPE_SRV:
      p = _add_rraw(p, rr->rraw, r->msg);
    default:
      break;
    }
    switch (rrtype) {
    case RTYPE_A:
    case RTYPE_AAAA:
    case RTYPE_PTR:
    case RTYPE_SRV:
      p = _add_str(p, ")\n");
    default:
      break;
    }
  }
  ssize_t size = p - buf;
  if (size > 0)
    xwrite(1, buf, size);
#endif
  return ret;
}

static cdata_t mdnsq_read_rr(cdata_t p, rr_t *rr, cdata_t const msg, int qm) {
  /* https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2 */
  rr->lbls = 0;
  rr->rrname = p;
  p = mdnsq_count_labels(p, &rr->lbls, msg);
  p = mdnsq_read_ntohs(p, &rr->rrtype);
  p = mdnsq_read_ntohs(p, &rr->rrclass_);
  if (qm)
    return p;
  /* https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3 */
  rr->lbls = 0;
  p = mdnsq_read_ntohl(p, &rr->ttl);
  p = mdnsq_read_ntohs(p, &rr->rdlen);
  qtype_t rrtype = rr->rrtype;
  cdata_t r = p;
  rr->rraw = r;
  p += rr->rdlen;
  switch (rrtype) {
  case RTYPE_SRV:
    r += 6; /* skip unused: priority, weight & port */
    /* FALLTHROUGH */
  case RTYPE_PTR:
    r = mdnsq_count_labels(r, &rr->lbls, msg);
    break;
  default:
    break;
  }
  return p;
}

/* vo[MAX_OFFETS] is valid offsets array */
static cdata_t _validate_label(cdata_t p, ssize_t size, response_t *resp) {
  cdata_t const msg = resp->msg;
  const ssize_t msize = resp->size;
  uint16_t *vo = resp->vo;
  cdata_t const start = p;

  for (uint16_t n; /**/; /**/) {
    if (size < 1)
      return NULL;
    n = *p;
    if ((n & 0xc0) == 0xc0) {
      if ((size -= 2) < 0)
        return NULL;
      p = mdnsq_read_ntohs(p, &n);
      n &= 0x3fff; /* offset */
      if (msg + n >= start)
        return NULL;
      for (int i = 0; i < MAX_OFFSETS && vo[i]; ++i) {
        if (n == vo[i]) {
          /* check total name length */
          cdata_t r = msg + n, s = r;
          r = _validate_label(r, msize - n, resp);
          if (!r)
            return NULL;
          ssize_t size1 = (p - start);
          ssize_t size2 = (r - s);
          if (size1 + size2 > MAX_LABEL_LENGTH)
            return NULL;
          return p;
        }
      }
      return NULL;
    } else if ((n & 0xc0) == 0) {
      cdata_t r = p;
      if ((size -= n + 1) < 0)
        return NULL;
      p += n + 1;
      if (p - start > MAX_LABEL_LENGTH)
        return NULL;
      if (n == 0)
        return p;
      _offset_save(vo, r - msg);
    } else
      return NULL;
  }
}

/* discard invalid RR's */
static uint16_t _validate_response(response_t *resp, unsigned n, ssize_t size) {
  cdata_t p = resp->msg + DNS_PACKET_HEADER_SIZE, r;
  const uint16_t nq = resp->questions;
  uint16_t rdlen, type, class;

  /* questions: rrname, rrtype, rrclass_ */
  for (unsigned i = 0; i < n; ++i) {
    /* https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2 */
    cdata_t s = p; /* label start */
    p = _validate_label(p, size, resp);
    if (!p)
      return i;
    size -= (p - s);
    if ((size -= 4) < 0)
      return i;
    p = mdnsq_read_ntohs(p, &type);
    p = mdnsq_read_ntohs(p, &class);
    if ((class & 0x7fff) != 0x0001) /* mask cash_flush */
      return i;
    if (i < nq) /* QM question */
      continue;
    /* https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3 */
    if ((size -= 6) < 0)
      return i;
    p += 4; /* skip TTL */
    p = mdnsq_read_ntohs(p, &rdlen);
    if (size < rdlen)
      return i;
    r = p;
    switch (type) {
    case RTYPE_A:
      if (rdlen != 4)
        return i;
      break;
    case RTYPE_AAAA:
      if (rdlen != 16)
        return i;
      break;
    case RTYPE_SRV:
      if (size < 6)
        return i;
      r += 6; /* skip priority, weight & port */
      /* FALLTHROUGH */
    case RTYPE_PTR:
      s = r;
      if (!(r = _validate_label(r, type == RTYPE_SRV ? size - 6 : size, resp)))
        return i;
      if ((r - s) > rdlen)
        return i;
      break;
    default:
      break;
    }
    size -= rdlen;
    p += rdlen;
  }
  return n;
}

static int mdnsq_read_response(mdnsq_t *s, cdata_t const msg, ssize_t size) {
  response_t r = {0};
  cdata_t p = msg;
  unsigned n;
  r.msg = msg;
  r.size = size;
  if ((size -= DNS_PACKET_HEADER_SIZE) < 0)
    return -1;
  p = mdnsq_read_ntohs(p, &r.id);
  p = mdnsq_read_ntohs(p, &r.flags);
  /* RFC6762 sections 18.2, 18.3, 18.8, 18.11 */
  /* QR=1, OPCODE=0, Z=0, RCODE=0 */
  if ((r.flags & 0xf84f) != 0x8000)
    return -1;
  p = mdnsq_read_ntohs(p, &r.questions);
  p = mdnsq_read_ntohs(p, &r.answer_rr);
  p = mdnsq_read_ntohs(p, &r.authority_rr);
  p = mdnsq_read_ntohs(p, &r.additional_rr);
  n = r.questions + r.answer_rr + r.authority_rr + r.additional_rr;
  n = _validate_response(&r, n, size);
  if (n > 0) {
    rr_t rr[n];
    r.rr = rr;
    for (unsigned i = 0; i < n; ++i) {
      const int qm = i < r.questions;
      p = mdnsq_read_rr(p, &r.rr[i], msg, qm);
    }
    n = cb_response(s, &r, n);
  }
  return n;
}

#if (FUZZ+0)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mdnsq_t s = {0};
  mdnsq_read_response(&s, data, size);
  return 0;
}
#else
static const char DISCO_NAME[] = "_services._dns-sd._udp.local.";

static const char _usage[] = ""
"  usage: mdnsq [options] [name]\n"
"\n"
"options:\n"
"  -6       use ipv6\n"
"  -t[type] RR type (A=1, AAAA=28, PTR=12, ANY=255)\n"
"  -w[ms]   timeout in milliseconds\n"
"\n"
"example: mdnsq -w500 -t12 _ssh._tcp.local."
"\n";

/* FF02::FB */
#define IN6ADDR_MDNS_INIT ((struct in6_addr){ { { \
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, \
} } })

/* 224.0.0.251 */
#define INADDR_MDNS_INIT ((in_addr_t)htonl(0xe00000fb))

/* bind to INADDR_ANY, any port */
static int mdnsq_init(mdnsq_t *s) {
  sockaddr_t sa = {0};
  socklen_t addrlen;
  int family;
  int ret;

  if (s->ipv6) {
    addrlen = sizeof(sa.s6);
    family = sa.s6.sin6_family = AF_INET6;
  } else {
    addrlen = sizeof(sa.s4);
    family = sa.s4.sin_family = AF_INET;
  }

  if ((s->sock = ret = socket(family, SOCK_DGRAM, 0)) < 0)
    perror("socket");
  else if ((ret = bind(s->sock, &sa.s, addrlen)) < 0)
    perror("bind");

  /* initilize multicast destination address here */
  const uint16_t port = htons(5353);
  if (s->ipv6) {
    sa.s6.sin6_addr = IN6ADDR_MDNS_INIT;
    sa.s6.sin6_port = port;
  } else {
    sa.s4.sin_addr.s_addr = INADDR_MDNS_INIT;
    sa.s4.sin_port = port;
  }
  s->sa = sa;
  return ret;
}

static void mdnsq_fini(mdnsq_t *s) {
  close(s->sock);
}

static uint32_t qname2rraw(const char *qname, uint8_t rraw[]) {
  uint8_t *p = rraw;
  for (const char *q = qname, *s; *q; ++q) {
    for (s = q; *q && *q != '.'; ++q);
    int n = (q - s);
    *p++ = n;
    while (s < q)
      *p++ = *s++;
  }
  *p = '\0';
  return hash_name(rraw, NULL);
}

static int mdnsq_send_query1(mdnsq_t *s) {
  query_t *q = mdnsq_new_query(s);
  uint8_t rraw[MAX_LABEL_LENGTH];
  uint32_t h = qname2rraw(s->qname, rraw);
  if (mdnsq_packet_addq(q, NULL, rraw, s->qtype) < 0)
    return -1;
  mdnsq_adjust_timeout(s);
  s->qreqs[s->qnums++] = h;
  return mdnsq_udp_write(s, q->raw_data, q->raw_size);
}

static int mdnsq_udp_read(mdnsq_t *s, uint8_t *buf, int *bufsize) {
  ssize_t n = recv(s->sock, buf, *bufsize, MSG_DONTWAIT);
  *bufsize = n;
  if (s->dbg > 0) {
    xwrite(2, "RECV:\n", 6);
    _debug_hexdump(buf, n);
  }
  if (n > 0)
    n = mdnsq_read_response(s, buf, n);
  return (int)n; /* maybe no message yet */
}

static int mdnsq_loop(mdnsq_t *s) {
  struct timeval *tv = &s->tmout;
  const int fd = s->sock;
  const int nfds = fd + 1;
  fd_set fdset[2];
  int r = 0;

  for (int i = 0; i < 2; ++i)
    FD_ZERO(&fdset[i]);

  FD_SET(fd, &fdset[1]);
  for (;;) {
    FD_SET(fd, &fdset[0]);
    r = select(nfds, &fdset[0], &fdset[1], NULL, tv);
    if (r <= 0) /* error or time out*/
      break;

    if (FD_ISSET(fd, &fdset[0])) { /* read fdsset */
      /* excess bytes may be discarded if buffer is not big enough */
      uint8_t buf[MAX_UDP_MUL_IN];
      int size = sizeof(buf);
      r = mdnsq_udp_read(s, buf, &size);
    }

    if (FD_ISSET(fd, &fdset[1])) { /* write fdsset */
      FD_CLR(fd, &fdset[1]);
      r = mdnsq_send_query1(s);
    }

    if (r < 0)
      break;
  }

  return r;
}

static int mdnsq_name_isvalid(const char *qname) {
  const char *p = qname;
  for (char a, b = '.'; (a = *p); b = a, ++p)
    if (a == '.' && a == b)
      return 0; /* empty label */
  return p - qname <= MAX_LABEL_LENGTH && p > qname && p[-1] == '.';
}

static uint32_t _atou(const char *s) {
  uint32_t result = 0;
	for (/**/; *s; ++s) {
    if (*s < '0' || *s > '9')
      break;
    result *= 10;
    result -= (*s - '0');
	}
	result = -result;
	return result;
}

int main(int ac, char **av) {
  mdnsq_t s = {0};
  int ret;

  s.qname = DISCO_NAME;
  s.qtype = RTYPE_PTR;

  for (char *p = *++av; --ac; p = *++av) {
    if (*p == '-') {
      switch (*++p) {
      case '6':
        s.ipv6 = 1;
        break;
      case 'd':
        s.dbg++;
        break;
      case 't':
        s.qtype = _atou(++p);
        break;
      case 'w':
        s.tmout.tv_usec = 1000 * _atou(++p);
        break;
      default:
        xwrite(2, _usage, sizeof(_usage) - 1);
        return 1;
      }
    }
    else
      break;
  }

  if (*av)
    s.qname = *av;

  if (!mdnsq_name_isvalid(s.qname))
    return 1;

  ret = mdnsq_init(&s);
  if (ret >= 0)
    ret = mdnsq_loop(&s);
  mdnsq_fini(&s);
  return -ret;
}
#endif
