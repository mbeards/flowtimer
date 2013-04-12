#ifndef RIB_H
#define RIB_H

#define ALPHA 0.5

#include "flowtimer.h"

struct route {
  struct in_addr address;
  short prefix;

  long int rtt_sec;
  long int rtt_usec;

  struct route* last;
  struct route* next;
}

void update_route(long int rtt_sec, long int rtt_usec, struct in_addr* address);

#endif
