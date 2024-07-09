#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>

enum constants_ {
  MAX_UDP_MUL_IN = 16384,
  RTYPE_PTR = 12
};

static uint8_t msg[MAX_UDP_MUL_IN] = {
  0x00, 0x00, /* id */
  0x84, 0x00, /* flags */
  0x00, 0x01, /* Questions */
  0xff, 0xff, /* Answer RRs*/
  0x00, 0x00, /* Authority RRs */
  0x00, 0x00, /* Additional RRs  */
  /* \x09_services\x07_dns-sd\x04_udp\x05local\x00 */
  0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d,
  0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
  0x00, 0x0c, 0x00, 0x01
};

static const uint8_t psym[64] = \
"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+";

int _utoa(uint32_t x, uint8_t *buf)
{
	int n = 0;
  for (;;) {
		++n;
		*buf++ = psym[x % 64];
		if ((x /= 64) == 0)
			break;
	}
	*buf = '\0';
	return n;
}

static uint8_t *_put_htons(uint8_t *p, uint16_t v) {
  *(uint16_t *)p = htons(v);
  return p + 2;
}
static uint8_t *_put_htonl(uint8_t *p, uint32_t v) {
  *(uint32_t *)p = htonl(v);
  return p + 4;
}

static uint8_t *_put_3lbls(uint8_t *p, uint32_t x) {
  p = _put_htons(p, 0xc00c);    /* owner offset */
  p = _put_htons(p, RTYPE_PTR); /* type */
  p = _put_htons(p, 0x0001);    /* class */
  p = _put_htonl(p, 120);       /* TTL */
  uint8_t *q = p;               /* rdlen pos */ 
  p += 2;
  for (int i = 0; i < 3; ++i) {
    int n = _utoa(x + i, p + 1);
    *p = n;
    p += n + 1;
  }
  *p++ = '\0';
  uint16_t rdlen = p - q - 2;
  _put_htons(q, rdlen);
  return p;
}

int main()
{
  uint8_t *p = msg + 46; /* hdr + q1 */
  uint32_t start = 1100, end = start + 642, x;
  for (x = start; x < end; ++x) {
    p = _put_3lbls(p, x);
    if (MAX_UDP_MUL_IN - 20 < p - msg)
      break;
  }
  _put_htons(msg + 6, x);
  write(1, msg, p - msg);
  return 0;
}