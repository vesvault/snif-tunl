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

typedef struct snifl {
    struct snifl_func *inchain;
    struct snifl_func *outchain;
    void *arg;
    unsigned short mtu;
} snifl;

typedef struct snifl_func {
    int (* func)(const struct snifl *tunl, const struct snifl_func *func, const void *pkt, int len);
    struct snifl_lstn *protochain;
    void *arg;
} snifl_func;

typedef struct snifl_af {
    struct snifl_sock *(* pkt2sock)(const void *pkt);
    void *(* sock2pkt)(void *pkt, const struct snifl_sock *sock);
    void *(* pkt2pkt)(void *pkt, const void *src);
    int (* sendpkt)(const struct snifl *tunl, void *pkt, int protolen);
    int (* cmpaddr)(const void *addr1, const void *addr2);
    int (* matchpkt)(const void *addr, const void *pkt);
    unsigned short (* pchksum)(const void *pdata, const void *pkt, int len);
} snifl_af;

typedef struct snifl_lstn {
    int (* func)(const struct snifl *tunl, const struct snifl_lstn *lstn, const void *payload, int paylen, const void *pkt, const struct snifl_af *af);
    void *addr;
    void *arg;
    unsigned short lport;
    unsigned short rport;
} snifl_lstn;

#ifndef SNIFL_MTU
#define	SNIFL_MTU		4096
#endif

#define	SNIFL_E_OK		0
#define	SNIFL_E_PARAM	-100
#define	SNIFL_E_IPHDR	-101
#define	SNIFL_E_FRAG		-102
#define	SNIFL_E_THDR		-103
#define	SNIFL_E_SOCK		-104
#define	SNIFL_E_APP		-105


#define	snifl_a2c(a)	((const unsigned char *)&a)
#define	snifl_a2v(a)	((unsigned char *)&a)
#define	snifl_a2h(a)	((snifl_a2c(a)[0] << 8) | snifl_a2c(a)[1])
#define	snifl_a2l(a)	((((((snifl_a2c(a)[0] << 8) | snifl_a2c(a)[1]) << 8) | snifl_a2c(a)[2]) << 8) | snifl_a2c(a)[3])
#define	snifl_h2a(a, h)	(snifl_a2v(a)[0] = h >> 8, snifl_a2v(a)[1] = h)
#define	snifl_l2a(a, l)	(snifl_a2v(a)[0] = l >> 24, snifl_a2v(a)[1] = l >> 16, snifl_a2v(a)[2] = l >> 8, snifl_a2v(a)[3] = l)

int snifl_pktin(const struct snifl *tunl, const void *pk, int len);
int snifl_pktout(const struct snifl *tunl, const void *pk, int len);
int snifl_chain(const struct snifl *tunl, const struct snifl_func *chain, const void *pk, int len);
int snifl_protochain(const struct snifl *tunl, const struct snifl_lstn *chain, const void *payload, int paylen, const void *pk, unsigned short lport, unsigned short rport, const struct snifl_af *af);
unsigned short snifl_chksum(unsigned short init, const void *data, int len);
