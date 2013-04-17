#ifndef FLOW_H
#define FLOW_H

#include "flowtimer.h"

#define F_OPEN 0
#define F_MATCHED 1
#define F_EXPIRE 2

struct flow {
  struct in_addr ip_src;
  struct in_addr ip_dst;
  struct timeval timestamp;
  struct timeval last_seen;
  int route;
  short expiry;
  LIST_ENTRY(flow) pointers;
};

void print_flow(struct flow * f);
int match_flow(struct flow * f);
void insert_flow(struct flow * f);
struct timeval rtt_get(struct flow * f);
#endif
