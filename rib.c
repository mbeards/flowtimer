#include "rib.h"

void update_route(long int rtt_sec, long int rtt_usec, struct in_addr* address) {

  //find route that matches the address
  struct route* r, curr;

  for(curr = routingtable; curr != NULL; curr=curr->next) {
    if(curr->address.s_addr == address.s_addr) {
      r = curr;
      break;
    }
  }
  if(r == NULL) {
    r = (struct route*)(malloc(sizeof route));
    memcpy(&r->address, address, sizeof in_addr);
    r->rtt_sec = rtt_sec;
    r->rtt_usec = rtt_usec;
    r->last = curr;
    r->next = NULL;
    if(curr != NULL) {
      curr->next = r;
    }
    return;
  }


  //update the rtt
 
  int64_t rtt = (r->rtt_sec * 1000000) + r->rtt_usec;
  int64_t new_rtt = (rtt_sec * 1000000) + rtt_usec;

  //Let's have ALPHA = 0.5 to simplify things for now
  int64_t out_rtt = (new_rtt>>2) + (rtt>>2);
  r->rtt_sec = out_rtt/1000000;
  r->rtt_usec = out_rtt%1000000;
}



void print_rib() {
  if(routingtable == NULL) {
    fprintf(stdout, "RIB is Empty. \n");
    return;
  }

  for(struct route* curr = routingtable; curr != NULL; curr=curr->next) {
    char addr_str[INET_ADDRSTRLEN];
    fprintf(stdout, "%16s/%2i %ld.%ld\n", inet_ntop(AF_INET, curr->in_addr, addr_str, INET_ADDRSTRLEN), curr->prefix, curr->rtt_sec, curr->rtt_usec);
  }
}
