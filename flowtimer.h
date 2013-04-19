#ifndef FLOWTIMER_H
#define FLOWTIMER_H

#define NOISY 0
#define FORCE_PREFIX_SIZE 32 
#define PACKET_COUNT -1

#include <pcap.h> 
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

#include "rib.h"
#include "flow.h"


LIST_HEAD(routing_table, route) route_head;
LIST_HEAD(flow_table, flow) flow_head;

int update_count;

int endcount;

#endif
