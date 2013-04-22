#ifndef FLOWTIMER_PROBE_H
#define FLOWTIMER_PROBE_H

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

#include "flow.h"

#define DEFDATALEN      56
#define MAXIPLEN  60
#define MAXICMPLEN  76

#define P_UNSENT 0
#define P_SENT 1

struct probe {
  struct in_addr ip_dst;
  struct timeval timestamp;
  struct route * route;
  short status;
  LIST_ENTRY(probe) pointers;
};

void probe_flows();

static void noresp(int ign);

static int in_cksum(unsigned short *buf, int sz);

void ping(struct in_addr * addr);

void probe_request(struct route * r, struct in_addr * address);

void send_probe(struct probe* p);

void next_probe();

void handle_probe();

int pingsock;
#endif
