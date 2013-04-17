#include "rib.h"

void update_route(long int rtt_sec, long int rtt_usec, struct in_addr* address) {

  //find route that matches the address
  struct route* r;
  struct route* curr;
  char addr_str[INET_ADDRSTRLEN];
  char r_addr_str[INET_ADDRSTRLEN];


  LIST_FOREACH(curr, &route_head, pointers) {
    short shamt = 32-curr->prefix;
    //make sure to switch to host byte order
    if(((unsigned long int)ntohl(curr->address.s_addr))>>shamt == ((unsigned long int)ntohl(address->s_addr))>>shamt) {
      r = curr;
      //update the rtt
      int64_t rtt = (r->rtt_sec * 1000000) + r->rtt_usec;
      int64_t new_rtt = (rtt_sec * 1000000) + rtt_usec;

      //Let's have ALPHA = 0.5 to simplify things for now
      int64_t out_rtt = (new_rtt>>2) + (rtt>>2);
      r->rtt_sec = out_rtt/1000000;
      r->rtt_usec = out_rtt%1000000;
      return;
    }
  }
  
  r = (struct route*)(malloc(sizeof(struct route)));
  memcpy(&r->address, address, sizeof(struct in_addr));
  r->rtt_sec = rtt_sec;
  r->rtt_usec = rtt_usec;
  r->prefix = 24;

  LIST_INSERT_HEAD(&route_head, r, pointers);


}



void print_rib() {
  fprintf(stdout, "Printing RIB\n--------------------\n");
  if(LIST_EMPTY(&route_head)) {
    fprintf(stdout, "RIB is Empty. \n");
    return;
  }

  struct route* curr;

  LIST_FOREACH(curr, &route_head, pointers) {
    char addr_str[INET_ADDRSTRLEN];
    fprintf(stdout, "%16s/%i %ld.%ld\n", inet_ntop(AF_INET, &curr->address, addr_str, INET_ADDRSTRLEN), curr->prefix, curr->rtt_sec, curr->rtt_usec);
  }
  fprintf(stdout, "--------------------\n");
}
