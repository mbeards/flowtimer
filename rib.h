#ifndef RIB_H
#define RIB_H

#define ALPHA 0.5

#include <sys/queue.h>
#include <netinet/in.h>
#include "flowtimer.h"


struct route {
  struct in_addr address;
  short prefix;

  long int rtt_sec;
  long int rtt_usec;

  LIST_ENTRY(route) pointers;
};

void update_route(long int rtt_sec, long int rtt_usec, struct in_addr* address);
void print_rib();
struct route* get_route(struct in_addr*);
#endif
