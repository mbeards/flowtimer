#include "flow.h"
#include "flowtimer.h"


void print_flow(struct flow * f) {
  char src_str[INET_ADDRSTRLEN];
  char dst_str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &f->ip_src, src_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &f->ip_dst, dst_str, INET_ADDRSTRLEN);
  fprintf(stdout,"%ld.%ld %s->%s\n",f->timestamp.tv_sec, f->timestamp.tv_usec, src_str, dst_str);
}

int match_flow(struct flow * f) {
  struct flow* curr;
  int traverse_size = 0;
  LIST_FOREACH(curr, &flow_head, pointers) {
    traverse_size++;
    //Expire old flows
    if(curr->last_seen.tv_sec - curr->timestamp.tv_sec > F_EXPIRE_WINDOW) {
      curr->expiry = F_EXPIRED;
      fprintf(stdout, "Expired flow: ");
      print_flow(curr);
    }

    if(f->ip_src.s_addr == curr->ip_src.s_addr && f->ip_dst.s_addr == curr->ip_dst.s_addr && curr->route == f->route) {
      //Update the last seen timestamp for the flow
      curr->last_seen = f->timestamp;
      if(curr->expiry == F_EXPIRED || curr->expiry == F_MATCHED) {
        curr->expiry = F_OPEN;
        curr->timestamp= f->timestamp;
      }
      return(1);
    } else if(f->ip_dst.s_addr == curr->ip_src.s_addr && f->ip_src.s_addr == curr->ip_dst.s_addr && curr->route == f->route && curr->expiry == F_OPEN) {
      curr->expiry = F_MATCHED;
      return(-1);
    }
  }
  return(0);
}

void insert_flow(struct flow * f) {
  LIST_INSERT_HEAD(&flow_head, f, pointers);
  f->expiry = F_OPEN;
}

struct timeval rtt_get(struct flow * f) {
  struct timeval rtt;

  //return f.timestamp - curr.timestamp
  struct flow* curr;
  LIST_FOREACH(curr, &flow_head, pointers) {
    if(f->ip_dst.s_addr == curr->ip_src.s_addr && f->ip_src.s_addr == curr->ip_dst.s_addr && curr->route == f->route && curr->expiry == F_MATCHED) {
      int64_t ftime = (f->timestamp.tv_sec * 1000000) + f->timestamp.tv_usec;
      int64_t ctime = (curr->timestamp.tv_sec * 1000000) + curr->timestamp.tv_usec;

      ftime = ftime-ctime;
      rtt.tv_sec = ftime/1000000;
      rtt.tv_usec = ftime%1000000;

      //remove curr from flow table
      LIST_REMOVE(curr, pointers);
      free(curr);

      return rtt;
    }
  }
}

void last_seen(struct flow * f) {
  struct flow* curr;
  LIST_FOREACH(curr, &flow_head, pointers) {
    if(f->ip_dst.s_addr == curr->ip_dst.s_addr && f->ip_src.s_addr == curr->ip_src.s_addr && curr->route == f->route && curr->expiry != F_EXPIRED) {
      curr->last_seen = f->timestamp;
    }
  }
}
  


