--- apps/pkt-gen/pkt-gen.c.orig	2019-11-06 09:59:27 UTC
+++ apps/pkt-gen/pkt-gen.c
@@ -38,42 +38,40 @@
  */
 
 #define _GNU_SOURCE	/* for CPU_SET() */
-#include <stdio.h>
-#include <libnetmap.h>
-
-
-#include <sys/types.h>
-#include <sys/stat.h>
-#include <fcntl.h>
-#include <ctype.h>	// isprint()
-#include <string.h>
-#include <unistd.h>	// sysconf()
-#include <sys/poll.h>
-#include <sys/ioctl.h>
-#include <signal.h>
 #include <arpa/inet.h>	/* ntohs */
-#if !defined(_WIN32) && !defined(linux)
-#include <sys/sysctl.h>	/* sysctl */
-#endif
+#include <assert.h>
+#include <ctype.h>	// isprint()
+#include <errno.h>
+#include <fcntl.h>
 #include <ifaddrs.h>	/* getifaddrs */
+#include <libnetmap.h>
+#include <math.h>
 #include <net/ethernet.h>
 #include <netinet/in.h>
 #include <netinet/ip.h>
-#include <netinet/udp.h>
 #include <netinet/ip6.h>
+#include <netinet/udp.h>
+#ifndef NO_PCAP
+#include <pcap/pcap.h>
+#endif
+#include <pthread.h>
+#include <signal.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/ioctl.h>
+#include <sys/poll.h>
+#include <sys/stat.h>
+#if !defined(_WIN32) && !defined(linux)
+#include <sys/sysctl.h>	/* sysctl */
+#endif
+#include <sys/types.h>
+#include <unistd.h>	// sysconf()
 #ifdef linux
 #define IPV6_VERSION	0x60
 #define IPV6_DEFHLIM	64
 #endif
-#include <assert.h>
-#include <math.h>
 
-#include <pthread.h>
-
-#ifndef NO_PCAP
-#include <pcap/pcap.h>
-#endif
-
 #include "ctrs.h"
 
 static void usage(int);
@@ -184,14 +182,14 @@ static inline void CPU_SET(uint32_t i, cpuset_t *p)
 	do {struct timespec t0 = {0,0}; *(b) = t0; } while (0)
 #endif  /* __APPLE__ */
 
-const char *default_payload="netmap pkt-gen DIRECT payload\n"
+static const char *default_payload = "netmap pkt-gen DIRECT payload\n"
 	"http://info.iet.unipi.it/~luigi/netmap/ ";
 
-const char *indirect_payload="netmap pkt-gen indirect payload\n"
+static const char *indirect_payload = "netmap pkt-gen indirect payload\n"
 	"http://info.iet.unipi.it/~luigi/netmap/ ";
 
-int verbose = 0;
-int normalize = 1;
+static int verbose = 0;
+static int normalize = 1;
 
 #define VIRT_HDR_1	10	/* length of a base vnet-hdr */
 #define VIRT_HDR_2	12	/* length of the extenede vnet-hdr */
@@ -223,7 +221,7 @@ struct pkt {
     ((af) == AF_INET ? (p)->ipv4.f: (p)->ipv6.f)
 
 struct ip_range {
-	char *name;
+	const char *name;
 	union {
 		struct {
 			uint32_t start, end; /* same as struct in_addr */
@@ -237,7 +235,7 @@ struct ip_range {
 };
 
 struct mac_range {
-	char *name;
+	const char *name;
 	struct ether_addr start, end;
 };
 
@@ -272,6 +270,7 @@ struct glob_arg {
 	int nthreads;
 	int cpus;	/* cpus used for running */
 	int system_cpus;	/* cpus on the system */
+	int softchecksum;   /* Enable software UDP checksum calculation */
 
 	int options;	/* testing */
 #define OPT_PREFETCH	1
@@ -281,7 +280,7 @@ struct glob_arg {
 #define OPT_TS		16	/* add a timestamp */
 #define OPT_INDIRECT	32	/* use indirect buffers, tx only */
 #define OPT_DUMP	64	/* dump rx/tx traffic */
-#define OPT_RUBBISH	256	/* send wathever the buffers contain */
+#define OPT_RUBBISH	256	/* send whatever the buffers contain */
 #define OPT_RANDOM_SRC  512
 #define OPT_RANDOM_DST  1024
 #define OPT_PPS_STATS   2048
@@ -302,7 +301,7 @@ struct glob_arg {
 	int td_type;
 	void *mmap_addr;
 	char ifname[MAX_IFNAMELEN];
-	char *nmr_config;
+	const char *nmr_config;
 	int dummy_send;
 	int virt_header;	/* send also the virt_header */
 	char *packet_file;	/* -P option */
@@ -633,7 +632,7 @@ system_ncpus(void)
  * If there is no 4th number, then the 3rd is assigned to both #tx-rings
  * and #rx-rings.
  */
-int
+static int
 parse_nmr_config(const char* conf, struct nmreq_register *nmr)
 {
 	char *w, *tok;
@@ -738,7 +737,7 @@ checksum(const void *data, uint16_t len, uint32_t sum)
 
 	/* Checksum all the pairs of bytes first... */
 	for (i = 0; i < (len & ~1U); i += 2) {
-		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
+		sum += (uint16_t)ntohs(*((const uint16_t *)(addr + i)));
 		if (sum > 0xFFFF)
 			sum -= 0xFFFF;
 	}
@@ -810,91 +809,99 @@ update_ip(struct pkt *pkt, struct targ *t)
 	struct glob_arg *g = t->g;
 	struct ip ip;
 	struct udphdr udp;
-	uint32_t oaddr, naddr;
-	uint16_t oport, nport;
+	uint32_t soaddr, snaddr; /* Old and new source addresses */
+	uint16_t soport, snport;
+	uint32_t doaddr, dnaddr;
+	uint16_t doport, dnport; /* Old and new destination ports */
 	uint16_t ip_sum, udp_sum;
 
 	memcpy(&ip, &pkt->ipv4.ip, sizeof(ip));
 	memcpy(&udp, &pkt->ipv4.udp, sizeof(udp));
+
+	/* Warning: do {} while(false) is not a loop */
 	do {
 		ip_sum = udp_sum = 0;
-		naddr = oaddr = ntohl(ip.ip_src.s_addr);
-		nport = oport = ntohs(udp.uh_sport);
+		snaddr = soaddr = ntohl(ip.ip_src.s_addr);
+		snport = soport = ntohs(udp.uh_sport);
+		dnaddr = doaddr = ntohl(ip.ip_dst.s_addr);
+		dnport = doport = ntohs(udp.uh_dport);
+
+		/* Update source port and address */
 		if (g->options & OPT_RANDOM_SRC) {
 			ip.ip_src.s_addr = nrand48(t->seed);
 			udp.uh_sport = nrand48(t->seed);
-			naddr = ntohl(ip.ip_src.s_addr);
-			nport = ntohs(udp.uh_sport);
+			snaddr = ntohl(ip.ip_src.s_addr);
+			snport = ntohs(udp.uh_sport);
 			break;
 		}
-		if (oport < g->src_ip.port1) {
-			nport = oport + 1;
-			udp.uh_sport = htons(nport);
+		if (soport < g->src_ip.port1) {
+			snport = soport + 1;
+			udp.uh_sport = htons(snport);
 			break;
 		}
-		nport = g->src_ip.port0;
-		udp.uh_sport = htons(nport);
-		if (oaddr < g->src_ip.ipv4.end) {
-			naddr = oaddr + 1;
-			ip.ip_src.s_addr = htonl(naddr);
+		snport = g->src_ip.port0;
+		udp.uh_sport = htons(snport);
+		if (soaddr < g->src_ip.ipv4.end) {
+			snaddr = soaddr + 1;
+			ip.ip_src.s_addr = htonl(snaddr);
 			break;
 		}
-		naddr = g->src_ip.ipv4.start;
-		ip.ip_src.s_addr = htonl(naddr);
-	} while (0);
-	/* update checksums if needed */
-	if (oaddr != naddr) {
-		ip_sum = cksum_add(ip_sum, ~oaddr >> 16);
-		ip_sum = cksum_add(ip_sum, ~oaddr & 0xffff);
-		ip_sum = cksum_add(ip_sum, naddr >> 16);
-		ip_sum = cksum_add(ip_sum, naddr & 0xffff);
-	}
-	if (oport != nport) {
-		udp_sum = cksum_add(udp_sum, ~oport);
-		udp_sum = cksum_add(udp_sum, nport);
-	}
-	do {
-		naddr = oaddr = ntohl(ip.ip_dst.s_addr);
-		nport = oport = ntohs(udp.uh_dport);
+		snaddr = g->src_ip.ipv4.start;
+		ip.ip_src.s_addr = htonl(snaddr);
+
+		/* Update destination port and address */
 		if (g->options & OPT_RANDOM_DST) {
 			ip.ip_dst.s_addr = nrand48(t->seed);
 			udp.uh_dport = nrand48(t->seed);
-			naddr = ntohl(ip.ip_dst.s_addr);
-			nport = ntohs(udp.uh_dport);
+			dnaddr = ntohl(ip.ip_dst.s_addr);
+			dnport = ntohs(udp.uh_dport);
 			break;
 		}
-		if (oport < g->dst_ip.port1) {
-			nport = oport + 1;
-			udp.uh_dport = htons(nport);
+		if (doport < g->dst_ip.port1) {
+			dnport = doport + 1;
+			udp.uh_dport = htons(dnport);
 			break;
 		}
-		nport = g->dst_ip.port0;
-		udp.uh_dport = htons(nport);
-		if (oaddr < g->dst_ip.ipv4.end) {
-			naddr = oaddr + 1;
-			ip.ip_dst.s_addr = htonl(naddr);
+		dnport = g->dst_ip.port0;
+		udp.uh_dport = htons(dnport);
+		if (doaddr < g->dst_ip.ipv4.end) {
+			dnaddr = doaddr + 1;
+			ip.ip_dst.s_addr = htonl(dnaddr);
 			break;
 		}
-		naddr = g->dst_ip.ipv4.start;
-		ip.ip_dst.s_addr = htonl(naddr);
+		dnaddr = g->dst_ip.ipv4.start;
+		ip.ip_dst.s_addr = htonl(dnaddr);
 	} while (0);
-	/* update checksums */
-	if (oaddr != naddr) {
-		ip_sum = cksum_add(ip_sum, ~oaddr >> 16);
-		ip_sum = cksum_add(ip_sum, ~oaddr & 0xffff);
-		ip_sum = cksum_add(ip_sum, naddr >> 16);
-		ip_sum = cksum_add(ip_sum, naddr & 0xffff);
+
+	/* update checksums if needed */
+	if (g->softchecksum) {
+	if (soaddr != snaddr) {
+		ip_sum = cksum_add(ip_sum, ~soaddr >> 16);
+		ip_sum = cksum_add(ip_sum, ~soaddr & 0xffff);
+		ip_sum = cksum_add(ip_sum, snaddr >> 16);
+		ip_sum = cksum_add(ip_sum, snaddr & 0xffff);
 	}
-	if (oport != nport) {
-		udp_sum = cksum_add(udp_sum, ~oport);
-		udp_sum = cksum_add(udp_sum, nport);
+	if (soport != snport) {
+		udp_sum = cksum_add(udp_sum, ~soport);
+		udp_sum = cksum_add(udp_sum, snport);
 	}
+	if (doaddr != dnaddr) {
+		ip_sum = cksum_add(ip_sum, ~doaddr >> 16);
+		ip_sum = cksum_add(ip_sum, ~doaddr & 0xffff);
+		ip_sum = cksum_add(ip_sum, dnaddr >> 16);
+		ip_sum = cksum_add(ip_sum, dnaddr & 0xffff);
+	}
+	if (doport != dnport) {
+		udp_sum = cksum_add(udp_sum, ~doport);
+		udp_sum = cksum_add(udp_sum, dnport);
+	}
 	if (udp_sum != 0)
 		udp.uh_sum = ~cksum_add(~udp.uh_sum, htons(udp_sum));
 	if (ip_sum != 0) {
 		ip.ip_sum = ~cksum_add(~ip.ip_sum, htons(ip_sum));
 		udp.uh_sum = ~cksum_add(~udp.uh_sum, htons(ip_sum));
 	}
+	}
 	memcpy(&pkt->ipv4.ip, &ip, sizeof(ip));
 	memcpy(&pkt->ipv4.udp, &udp, sizeof(udp));
 }
@@ -908,81 +915,91 @@ update_ip6(struct pkt *pkt, struct targ *t)
 	struct glob_arg *g = t->g;
 	struct ip6_hdr ip6;
 	struct udphdr udp;
-	uint16_t udp_sum;
-	uint16_t oaddr, naddr;
-	uint16_t oport, nport;
-	uint8_t group;
+	uint16_t udp_sum, ip_sum;
+	uint16_t soaddr, snaddr;
+	uint16_t soport, snport;
+	uint16_t doaddr, dnaddr;
+	uint16_t doport, dnport;
+	uint8_t sgroup, dgroup;
 
 	memcpy(&ip6, &pkt->ipv6.ip, sizeof(ip6));
 	memcpy(&udp, &pkt->ipv6.udp, sizeof(udp));
+
+	/* Warning: do {} while(false) is not a loop */
 	do {
 		udp_sum = 0;
-		group = g->src_ip.ipv6.sgroup;
-		naddr = oaddr = ntohs(ip6.ip6_src.s6_addr16[group]);
-		nport = oport = ntohs(udp.uh_sport);
+		ip_sum = 0;
+		sgroup = g->src_ip.ipv6.sgroup;
+		snaddr = soaddr = ntohs(ip6.ip6_src.s6_addr16[sgroup]);
+		snport = soport = ntohs(udp.uh_sport);
+		dgroup = g->dst_ip.ipv6.sgroup;
+		dnaddr = doaddr = ntohs(ip6.ip6_dst.s6_addr16[dgroup]);
+		dnport = doport = ntohs(udp.uh_dport);
+
+		/* Update source port and address */
 		if (g->options & OPT_RANDOM_SRC) {
-			ip6.ip6_src.s6_addr16[group] = nrand48(t->seed);
+			ip6.ip6_src.s6_addr16[sgroup] = nrand48(t->seed);
 			udp.uh_sport = nrand48(t->seed);
-			naddr = ntohs(ip6.ip6_src.s6_addr16[group]);
-			nport = ntohs(udp.uh_sport);
+			snaddr = ntohs(ip6.ip6_src.s6_addr16[sgroup]);
+			snport = ntohs(udp.uh_sport);
 			break;
 		}
-		if (oport < g->src_ip.port1) {
-			nport = oport + 1;
-			udp.uh_sport = htons(nport);
+		if (soport < g->src_ip.port1) {
+			snport = soport + 1;
+			udp.uh_sport = htons(snport);
 			break;
 		}
-		nport = g->src_ip.port0;
-		udp.uh_sport = htons(nport);
-		if (oaddr < ntohs(g->src_ip.ipv6.end.s6_addr16[group])) {
-			naddr = oaddr + 1;
-			ip6.ip6_src.s6_addr16[group] = htons(naddr);
+		snport = g->src_ip.port0;
+		udp.uh_sport = htons(snport);
+		if (soaddr < ntohs(g->src_ip.ipv6.end.s6_addr16[sgroup])) {
+			snaddr = soaddr + 1;
+			ip6.ip6_src.s6_addr16[sgroup] = htons(snaddr);
 			break;
 		}
-		naddr = ntohs(g->src_ip.ipv6.start.s6_addr16[group]);
-		ip6.ip6_src.s6_addr16[group] = htons(naddr);
-	} while (0);
-	/* update checksums if needed */
-	if (oaddr != naddr)
-		udp_sum = cksum_add(~oaddr, naddr);
-	if (oport != nport)
-		udp_sum = cksum_add(udp_sum,
-		    cksum_add(~oport, nport));
-	do {
-		group = g->dst_ip.ipv6.egroup;
-		naddr = oaddr = ntohs(ip6.ip6_dst.s6_addr16[group]);
-		nport = oport = ntohs(udp.uh_dport);
+		snaddr = ntohs(g->src_ip.ipv6.start.s6_addr16[sgroup]);
+		ip6.ip6_src.s6_addr16[sgroup] = htons(snaddr);
+
+		/* Update destination port and address */
 		if (g->options & OPT_RANDOM_DST) {
-			ip6.ip6_dst.s6_addr16[group] = nrand48(t->seed);
+			ip6.ip6_dst.s6_addr16[dgroup] = nrand48(t->seed);
 			udp.uh_dport = nrand48(t->seed);
-			naddr = ntohs(ip6.ip6_dst.s6_addr16[group]);
-			nport = ntohs(udp.uh_dport);
+			dnaddr = ntohs(ip6.ip6_dst.s6_addr16[dgroup]);
+			dnport = ntohs(udp.uh_dport);
 			break;
 		}
-		if (oport < g->dst_ip.port1) {
-			nport = oport + 1;
-			udp.uh_dport = htons(nport);
+		if (doport < g->dst_ip.port1) {
+			dnport = doport + 1;
+			udp.uh_dport = htons(dnport);
 			break;
 		}
-		nport = g->dst_ip.port0;
-		udp.uh_dport = htons(nport);
-		if (oaddr < ntohs(g->dst_ip.ipv6.end.s6_addr16[group])) {
-			naddr = oaddr + 1;
-			ip6.ip6_dst.s6_addr16[group] = htons(naddr);
+		dnport = g->dst_ip.port0;
+		udp.uh_dport = htons(dnport);
+		if (doaddr < ntohs(g->dst_ip.ipv6.end.s6_addr16[dgroup])) {
+			dnaddr = doaddr + 1;
+			ip6.ip6_dst.s6_addr16[dgroup] = htons(dnaddr);
 			break;
 		}
-		naddr = ntohs(g->dst_ip.ipv6.start.s6_addr16[group]);
-		ip6.ip6_dst.s6_addr16[group] = htons(naddr);
+		dnaddr = ntohs(g->dst_ip.ipv6.start.s6_addr16[dgroup]);
+		ip6.ip6_dst.s6_addr16[dgroup] = htons(dnaddr);
 	} while (0);
-	/* update checksums */
-	if (oaddr != naddr)
+
+	if (g->softchecksum) {
+	/* update checksums if needed */
+	/* XXX Buggy code: incorrect checksum */
+	if (soaddr != snaddr)
+		udp_sum = cksum_add(~soaddr, snaddr);
+	if (soport != snport)
 		udp_sum = cksum_add(udp_sum,
-		    cksum_add(~oaddr, naddr));
-	if (oport != nport)
+		    cksum_add(~soport, snport));
+	if (doaddr != dnaddr)
 		udp_sum = cksum_add(udp_sum,
-		    cksum_add(~oport, nport));
+		    cksum_add(~doaddr, dnaddr));
+	if (doport != dnport)
+		udp_sum = cksum_add(udp_sum,
+		    cksum_add(~doport, dnport));
 	if (udp_sum != 0)
 		udp.uh_sum = ~cksum_add(~udp.uh_sum, udp_sum);
+	}
 	memcpy(&pkt->ipv6.ip, &ip6, sizeof(ip6));
 	memcpy(&pkt->ipv6.udp, &udp, sizeof(udp));
 }
@@ -1255,7 +1272,7 @@ send_packets(struct netmap_ring *ring, struct pkt *pkt
 /*
  * Index of the highest bit set
  */
-uint32_t
+static uint32_t
 msb64(uint64_t x)
 {
 	uint64_t m = 1ULL << 63;
@@ -2374,7 +2391,7 @@ usage(int errcode)
 "             for client-side ping-pong operation, and pong for server-side ping-pong operation.\n"
 "\n"
 "     -n count\n"
-"             Number of iterations of the pkt-gen function, with 0 meaning infinite).  In case of tx or rx,\n"
+"             Number of iterations of the pkt-gen function (with 0 meaning infinite).  In case of tx or rx,\n"
 "             count is the number of packets to receive or transmit.  In case of ping or pong, count is the\n"
 "             number of ping-pong transactions.\n"
 "\n"
@@ -2411,20 +2428,24 @@ usage(int errcode)
 "     -p threads\n"
 "             Number of threads to use.  By default, only a single thread is used to handle all the netmap\n"
 "             rings.  If threads is larger than one, each thread handles a single TX ring (in tx mode), a\n"
-"             single RX ring (in rx mode), or a TX/RX ring couple.  The number of threads must be less or\n"
-"             equal than the number of TX (or RX) ring available in the device specified by interface.\n"
+"             single RX ring (in rx mode), or a TX/RX ring pair.  The number of threads must be less than or\n"
+"             equal to the number of TX (or RX) rings available in the device specified by interface.\n"
 "\n"
 "     -T report_ms\n"
 "             Number of milliseconds between reports.\n"
 "\n"
+"     -U      Enable software checksum calculation\n"
+"             (mandatory for NIC drivers that didn' support\n"
+"             hardwarde checksum calc in netmap mode)\n"
+"\n"
 "     -w wait_for_link_time\n"
-"             Number of seconds to wait before starting the pkt-gen function, useuful to make sure that the\n"
+"             Number of seconds to wait before starting the pkt-gen function, useful to make sure that the\n"
 "             network link is up.  A network device driver may take some time to enter netmap mode, or to\n"
 "             create a new transmit/receive ring pair when netmap(4) requests one.\n"
 "\n"
 "     -R rate\n"
 "             Packet transmission rate.  Not setting the packet transmission rate tells pkt-gen to transmit\n"
-"             packets as quickly as possible.  On servers from 2010 on-wards netmap(4) is able to com-\n"
+"             packets as quickly as possible.  On servers from 2010 onward netmap(4) is able to com-\n"
 "             pletely use all of the bandwidth of a 10 or 40Gbps link, so this option should be used unless\n"
 "             your intention is to saturate the link.\n"
 "\n"
@@ -2470,7 +2491,7 @@ usage(int errcode)
 "\n"
 "     -C tx_slots[,rx_slots[,tx_rings[,rx_rings]]]\n"
 "             Configuration in terms of number of rings and slots to be used when opening the netmap port.\n"
-"             Such configuration has effect on software ports created on the fly, such as VALE ports and\n"
+"             Such configuration has an effect on software ports created on the fly, such as VALE ports and\n"
 "             netmap pipes.  The configuration may consist of 1 to 4 numbers separated by commas: tx_slots,\n"
 "             rx_slots, tx_rings, rx_rings.  Missing numbers or zeroes stand for default values.  As an\n"
 "             additional convenience, if exactly one number is specified, then this is assigned to both\n"
@@ -2486,7 +2507,7 @@ usage(int errcode)
 "				OPT_INDIRECT	32 (use indirect buffers)\n"
 "				OPT_DUMP	64 (dump rx/tx traffic)\n"
 "				OPT_RUBBISH	256\n"
-"					(send wathever the buffers contain)\n"
+"					(send whatever the buffers contain)\n"
 "				OPT_RANDOM_SRC  512\n"
 "				OPT_RANDOM_DST  1024\n"
 "				OPT_PPS_STATS   2048\n"
@@ -2722,7 +2743,7 @@ main_thread(struct glob_arg *g)
 
 struct td_desc {
 	int ty;
-	char *key;
+	const char *key;
 	void *f;
 	int default_burst;
 };
@@ -2742,7 +2763,7 @@ tap_alloc(char *dev)
 {
 	struct ifreq ifr;
 	int fd, err;
-	char *clonedev = TAP_CLONEDEV;
+	const char *clonedev = TAP_CLONEDEV;
 
 	(void)err;
 	(void)dev;
@@ -2834,6 +2855,7 @@ main(int arc, char **argv)
 	g.dst_ip.name = "10.1.0.1";
 	g.dst_mac.name = "ff:ff:ff:ff:ff:ff";
 	g.src_mac.name = NULL;
+	g.softchecksum = 0;
 	g.pkt_size = 60;
 	g.pkt_min_size = 0;
 	g.nthreads = 1;
@@ -2847,7 +2869,7 @@ main(int arc, char **argv)
 	g.wait_link = 2;	/* wait 2 seconds for physical ports */
 
 	while ((ch = getopt(arc, argv, "46a:f:F:Nn:i:Il:d:s:D:S:b:c:o:p:"
-	    "T:w:WvR:XC:H:rP:zZAhBM:")) != -1) {
+	    "T:w:WvR:UXC:H:rP:zZAhBM:")) != -1) {
 
 		switch(ch) {
 		default:
@@ -2962,6 +2984,10 @@ main(int arc, char **argv)
 
 		case 'T':	/* report interval */
 			g.report_interval = atoi(optarg);
+			break;
+
+		case 'U':   /* Enable software checksum calculation */
+			g.softchecksum = 1;
 			break;
 
 		case 'w':
