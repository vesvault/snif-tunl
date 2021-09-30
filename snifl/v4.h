/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 **************************************************************************/

typedef struct snifl_v4 {
    uint8_t verlen;
    uint8_t dscp;
    uint16_t len;
    uint16_t id;
    uint16_t foffs;
    uint8_t ttl;
    uint8_t proto;
    uint16_t chksum;
    uint32_t srcaddr;
    uint32_t dstaddr;
    char data[0];
} snifl_v4;

typedef struct snifl_v4_sockaddr {
    uint32_t raddr;
    uint32_t laddr;
} snifl_v4_sockaddr;

#define	SNIFL_V4F_MF		0x2000
#define	SNIFL_V4F_DF		0x4000

#define	snifl_v4_ok(v4)	(((v4)->verlen & 0xf0) == 0x40)
#define	snifl_v4_hdrlen(v4)	(((v4)->verlen & 0x0f) << 2)
#define	snifl_v4_data(v4)	((void *)&(v4)->data[snifl_v4_hdrlen(v4) - offsetof(snifl_v4, data)])
#define	snifl_v4_datalen(v4)	(snifl_a2h((v4)->len) - snifl_v4_hdrlen(v4))
#define	snifl_v4_istcp(v4)	((v4)->proto == 0x06)
#define	snifl_v4_isudp(v4)	((v4)->proto == 0x11)
#define	snifl_v4_isicmp(v4)	((v4)->proto == 0x01)

extern const struct snifl_af snifl_v4_af;

int snifl_v4_validate(const struct snifl *tunl, const struct snifl_func *func, const void *pkt, int len);
int snifl_v4_recvtcp(const struct snifl *tunl, const struct snifl_func *func, const void *pkt, int len);
int snifl_v4_recvudp(const struct snifl *tunl, const struct snifl_func *func, const void *pkt, int len);
