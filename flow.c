#include "flow.h"
#include "flowtimer.h"


void print_flow(struct flow * f) {
  fprintf(stdout,"%ld.%ld %s->%s\n",f->timestamp.tv_sec, f->timestamp.tv_usec, inet_ntoa(f->ip_src), inet_ntoa(f->ip_dst));
}

int match_flow(struct flow * f) {
  for(struct flow* curr = flowtable; curr != NULL; curr = curr->next) {
    if(f->ip_src.s_addr == curr->ip_src.s_addr && f->ip_dst.s_addr == curr->ip_dst.s_addr && curr->route == f->route) {
      //Update the last seen timestamp for the flow
      curr->last_seen = f->timestamp;
      return(1);
    } else if(f->ip_dst.s_addr == curr->ip_src.s_addr && f->ip_src.s_addr == curr->ip_dst.s_addr && curr->route == f->route) {
      return(-1);
    }
  }
  return(0);
}

void insert_flow(struct flow * f) {
  f->next = NULL;
  f->last = NULL;

  if(flowtable == NULL) {
    flowtable = f;
    return;
  }

  for(struct flow* curr = flowtable; curr != NULL; curr = curr->next) {
    if(curr->next == NULL) {
      curr->next = f;
      f->last = curr;
      return;
    }
  }
}

struct timeval rtt_get(struct flow * f) {
  struct timeval rtt;

  //return f.timestamp - curr.timestamp
  for(struct flow* curr = flowtable; curr != NULL; curr = curr->next) {
    if(f->ip_dst.s_addr == curr->ip_src.s_addr && f->ip_src.s_addr == curr->ip_dst.s_addr && curr->route == f->route) {
      rtt.tv_sec = f->timestamp.tv_sec - curr->timestamp.tv_sec;
      rtt.tv_usec = f->timestamp.tv_usec - curr->timestamp.tv_usec;

      //remove curr from flow table
      if(curr->last == NULL) {
        flowtable = curr->next;
      } else {
        curr->last->next = curr->next;
      }
      if(curr->next != NULL) {
        curr->next->last = curr->last;
      }
      if(curr == flowtable) {
        flowtable = NULL;
      }

      return rtt;
    }
  }
}
  


