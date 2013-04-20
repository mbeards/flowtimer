#include <sys/socket.h> 
#include <netinet/in.h> 
#include <stdio.h>
#include <stdlib.h> 
#include <errno.h> 
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "flowtimer_probe.h"


static char *hostname = NULL;

void probe_flows() {
  struct flow* curr;
  LIST_FOREACH(curr, &flow_head, pointers) {
      fprintf(stdout, "probing ");
      print_flow(curr);
    //if(curr->expiry == F_EXPIRED) {
      ping(&curr->ip_dst);
    //}
  }
}

static void noresp(int ign)
{
  printf("No response from %s\n", hostname);
  exit(0);
}

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

void ping(struct in_addr * addr) {
  int pingsock, c;
  struct sockaddr_in pingaddr;
  struct hostent *h;
  struct icmp *pkt;
  char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];


  if ((pingsock = socket(AF_INET, SOCK_RAW, 1)) < 0) {  /* 1 == ICMP */
    perror("ping: creating a raw socket");
    exit(1);
  }


  memset(&pingaddr, 0, sizeof(struct sockaddr_in));
  
  pingaddr.sin_family = AF_INET;

  //if (!(h = gethostbyname(host))) {
  //  printf("unknown host %s\n", host);
  //  exit(1);
  //}

  memcpy(&pingaddr.sin_addr, addr, sizeof(pingaddr.sin_addr));
  //hostname = h->h_name;

  pkt = (struct icmp *) packet;
  memset(pkt, 0, sizeof(packet));
  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));

  c = sendto(pingsock, packet, sizeof(packet), 0, (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));

  if (c < 0 || c != sizeof(packet)) {
    if (c < 0)
      perror("ping: sendto");
    printf("write incomplete\n");
    exit(1);
  }

  inet_ntop(AF_INET, addr, hostname, INET_ADDRSTRLEN); 
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
      struct ip *iphdr = (struct iphdr *) packet;

      pkt = (struct icmp *) (packet + (iphdr->ip_hl << 2)); /* skip ip hdr */
      if (pkt->icmp_type == ICMP_ECHOREPLY)
        break;
    }
  }
  printf("%s is alive!\n", inet_ntoa(*addr));
  return;

}

void probe_request(struct route * r, struct in_addr * address) {
  struct probe * p = malloc(sizeof(struct probe));

  memcpy(&p->ip_dst, address, sizeof(struct in_addr));
  //Don't set timestamp here.  Set it when we dispatch
  p->status = P_UNSENT;
  p->route = r;

  LIST_INSERT_HEAD(&probe_head, p, pointers);
}

void send_probe(struct probe * p) {
  if(p->status == P_SENT) {
    return;
  }
  /* Probing process:
   * 1. Make sockaddr_in from the struct probe
   * LOAD CORRECT ROUTE INTO KERNEL FIB
   * 2. Send the packet
   * GO BACK TO OLD ROUTE IN KERNEL FIB
   * 3. Mark the probe's timestamp
   * 4. Mark the probe as P_SENT */
  int c;
  struct sockaddr_in pingaddr;
  struct hostent *h;
  struct icmp *pkt;
  char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];


  memset(&pingaddr, 0, sizeof(struct sockaddr_in));
  
  pingaddr.sin_family = AF_INET;

  memcpy(&pingaddr.sin_addr, &p->ip_dst, sizeof(pingaddr.sin_addr));

  pkt = (struct icmp *) packet;
  memset(pkt, 0, sizeof(packet));
  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));

  c = sendto(pingsock, packet, sizeof(packet), 0, (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));

  if (c < 0 || c != sizeof(packet)) {
    if (c < 0)
      perror("ping: sendto");
    printf("write incomplete\n");
    return;
  }
  p->status = P_SENT;

  return;

}

void next_probe() {
  if(LIST_FIRST(&probe_head)) {
    struct probe * p = LIST_FIRST(&probe_head);
    send_probe(p);
    //FOR NOW WE DELETE THE PROBE.  DON'T ACTUALLY DO THIS
    LIST_REMOVE(p, pointers);
    free(p);
  }

}
