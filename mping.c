/* vi: set sw=4 ts=4: */
/*
 * $Id: busybox-0.47.shar,v 1.1 2000/11/19 10:41:15 erich-roncarolo Exp $
 * Mini ping implementation for busybox
 *
 * Copyright (C) 1999 by Randolph Chung <tausq@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * This version of ping is adapted from the ping in netkit-base 0.10,
 * which is:
 *
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 * 
 * Original copyright notice is retained at the end of this file.
 */
#define TRUE 1

#include <stdio.h> 
#include <string.h>
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h> 
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
 
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/signal.h>
#include <netinet.h> 

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/ip_icmp.h>


#define DEFDATALEN      56
#define MAXIPLEN  60
#define MAXICMPLEN  76
#define MAXPACKET 65468
#define MAX_DUP_CHK (8 * 128)
#define MAXWAIT         10
#define PINGINTERVAL    1   /* second */

#define O_QUIET         (1 << 0)

#define A(bit)    rcvd_tbl[(bit)>>3]  /* identify byte in array */
#define B(bit)    (1 << ((bit) & 0x07)) /* identify bit in byte */
#define SET(bit)  (A(bit) |= B(bit))
#define CLR(bit)  (A(bit) &= (~B(bit)))
#define TST(bit)  (A(bit) & B(bit))

static void ping(const char *host);

/* common routines */
static int in_cksum(unsigned short *buf, int sz)
{
  int nleft = sz;
  int sum = 0;
  unsigned short *w = buf;
  unsigned short ans = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char *) (&ans) = *(unsigned char *) w;
    sum += ans;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  ans = ~sum;
  return (ans);
}

/* simple version */
static char *hostname = NULL;

static void noresp(int ign)
{
  printf("No response from %s\n", hostname);
  exit(0);
}

static void ping(const char *host)
{
  struct hostent *h;
  struct sockaddr_in pingaddr;
  struct icmp *pkt;
  int pingsock, c;
  char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];

  if ((pingsock = socket(AF_INET, SOCK_RAW, 1)) < 0) {  /* 1 == ICMP */
    perror("ping: creating a raw socket");
    exit(1);
  }

  /* drop root privs if running setuid */
  setuid(getuid());

  memset(&pingaddr, 0, sizeof(struct sockaddr_in));

  pingaddr.sin_family = AF_INET;
  if (!(h = gethostbyname(host))) {
    printf("unknown host %s\n", host);
    exit(1);
  }
  memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr));
  hostname = h->h_name;

  pkt = (struct icmp *) packet;
  memset(pkt, 0, sizeof(packet));
  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));

  c = sendto(pingsock, packet, sizeof(packet), 0,
         (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));

  if (c < 0 || c != sizeof(packet)) {
    if (c < 0)
      perror("ping: sendto");
    printf("write incomplete\n");
    exit(1);
  }

  signal(SIGALRM, noresp);
  alarm(5);         /* give the host 5000ms to respond */
  /* listen for replies */
  while (1) {
    struct sockaddr_in from;
    size_t fromlen = sizeof(from);

    if ((c = recvfrom(pingsock, packet, sizeof(packet), 0, (struct sockaddr *) &from, &fromlen)) < 0) {
      if (errno == EINTR)
        continue;
      perror("ping: recvfrom");
      continue;
    }
    if (c >= 76) {      /* ip + icmp */
      struct iphdr *iphdr = (struct iphdr *) packet;

      pkt = (struct icmp *) (packet + (iphdr->ihl << 2)); /* skip ip hdr */
      if (pkt->icmp_type == ICMP_ECHOREPLY)
        break;
    }
  }
  printf("%s is alive!\n", hostname);
  return;
}

extern int ping_main(int argc, char **argv)
{
  argc--;
  argv++;
  if (argc < 1)
    printf("args\n");
  ping(*argv);
  exit(TRUE);
}


/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
