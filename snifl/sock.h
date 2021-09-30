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

struct snifl_tcp;

typedef struct snifl_sock {
    const struct snifl *tunl;
    const struct snifl_af *af;
    int (* recv)(struct snifl_sock *sock, const void *buf, int len);
    int (* sendtcp)(struct snifl_sock *sock, struct snifl_tcp *tcp, int len, void *pkt);
    struct snifl_sock_q {
	struct snifl_sock_q *chain;
	uint32_t seq;
	uint16_t len;
	char data[0];
    } *queue;
    void *arg;
    uint32_t recvseq;
    uint16_t recvwin;
    uint16_t recvgap;
    uint32_t recvack;
    uint32_t sendseq;
    uint16_t sendwin;
    uint16_t sendgap;
    uint8_t proto;
    uint8_t flags;
    uint16_t lport;
    uint16_t rport;
    char addr[0];
} snifl_sock;

typedef struct snifl_accept {
    int (* accept)(struct snifl_sock *sock, const struct snifl_accept *ac);
    int (* recv)(struct snifl_sock *sock, const void *buf, int len);
    void *arg;
    unsigned short recvwin;
} snifl_accept;

typedef struct snifl_sock_q snifl_sock_q;

#define	SNIFL_SOCKF_FIN	SNIFL_TCPF_FIN
#define	SNIFL_SOCKF_SYN	SNIFL_TCPF_SYN
#define	SNIFL_SOCKF_RST	SNIFL_TCPF_RST
#define	SNIFL_SOCKF_ACK	SNIFL_TCPF_ACK
#define	SNIFL_SOCKF_EOF	0x20
#define	SNIFL_SOCKF_ERR	0x40
#define	SNIFL_SOCKF_END	0x80

#define	SNIFL_SHUT_RD	0
#define	SNIFL_SHUT_WR	1
#define	SNIFL_SHUT_RDWR	2
#define	SNIFL_SHUT_ERR	-1

int snifl_send(struct snifl_sock *sock, const void *buf, int len, int flags);
int snifl_shutdown(struct snifl_sock *sock, int mode);

int snifl_sock_sendtcp(struct snifl_sock *sock, struct snifl_tcp *tcp, int len, void *pkt);
int snifl_sock_tcpin(struct snifl_sock *sock, const struct snifl_tcp *tcp, int len);
int snifl_sock_cmptcp(const struct snifl_sock *sock, const struct snifl_tcp *tcp, const void *pkt, const struct snifl_af *af);
int snifl_sock_cmpsock(const struct snifl_sock *sock, const struct snifl_sock *s);
void snifl_sock_free(struct snifl_sock *sock);
