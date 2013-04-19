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

#define DEFDATALEN      56
#define MAXIPLEN  60
#define MAXICMPLEN  76



static void noresp(int ign);

static int in_cksum(unsigned short *buf, int sz);

void ping(struct in_addr * addr);

#endif
