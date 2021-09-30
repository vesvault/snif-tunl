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

typedef struct snifl_tcp {
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seq;
    uint32_t ack;
    uint8_t lenflg;
    uint8_t flags;
    uint16_t win;
    uint16_t chksum;
    uint16_t urg;
    char data[0];
} snifl_tcp;

#define	SNIFL_TCPF_FIN	0x01
#define	SNIFL_TCPF_SYN	0x02
#define	SNIFL_TCPF_RST	0x04
#define	SNIFL_TCPF_PSH	0x08
#define	SNIFL_TCPF_ACK	0x10

#define	snifl_tcp_hdrlen(tcp)	(((tcp)->lenflg >> 2) & 0x3c)
#define	snifl_tcp_data(tcp)		((void*)&(tcp)->data[snifl_tcp_hdrlen(tcp) - offsetof(snifl_tcp, data)])

struct snifl_sock *snifl_tcp2sock(const struct snifl_tcp *srctcp, const void *srcpkt, const struct snifl_af *af);
struct snifl_tcp *snifl_sock2tcp(void *pkt, const struct snifl_sock *sock);
struct snifl_tcp *snifl_tcp2tcp(void *pkt, const struct snifl_tcp *srctcp, const void *srcpkt, const struct snifl_af *af);
int snifl_sendtcp(const struct snifl *tunl, struct snifl_tcp *tcp, int datalen, void *pkt, const struct snifl_af *af);

int snifl_tcp_accept(const struct snifl *tunl, const struct snifl_lstn *lstn, const void *payload, int paylen, const void *pk, const struct snifl_af *af);
int snifl_tcp_reset(const struct snifl *tunl, const struct snifl_lstn *lstn, const void *payload, int paylen, const void *pk, const struct snifl_af *af);
