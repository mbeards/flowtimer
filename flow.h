#ifndef FLOW_H
#define FLOW_H

#include "flowtimer.h"

struct flow {
  struct in_addr ip_src;
  struct in_addr ip_dst;
  struct timeval timestamp;
  struct timeval last_seen;
  int route;
  struct flow* next;
  struct flow* last;
};

void print_flow(struct flow * f);
int match_flow(struct flow * f);
void insert_flow(struct flow * f);
struct timeval rtt_get(struct flow * f);
#endif
