#include "flowtimer_pcap.h"
#include "flow.h"



u_int16_t ethernet_handler (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  u_int caplen = pkthdr->caplen; /* length of portion present from bpf  */
  u_int length = pkthdr->len;    /* length of this packet off the wire  */
  struct ether_header *eptr;     /* net/ethernet.h                      */
  u_short ether_type;            /* the type of packet (we return this) */
  eptr = (struct ether_header *) packet;
  ether_type = ntohs(eptr->ether_type);

  if(NOISY) {fprintf(stdout," %d\n",length);} /* print len */
 
  return ether_type;
}

struct flow* flow_handler (u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct nread_ip* ip;   /* packet structure         */
  const struct nread_tcp* tcp; /* tcp structure            */
  u_int length = pkthdr->len;  /* packet header length  */
  u_int off, version;             /* offset, version       */
  int len;                        /* length holder         */

  ip = (struct nread_ip*)(packet + sizeof(struct ether_header));
  length -= sizeof(struct ether_header);
  tcp = (struct nread_tcp*)(packet + sizeof(struct ether_header) + sizeof(struct nread_ip));

  len     = ntohs(ip->ip_len); /* get packer length */
  version = IP_V(ip);          /* get ip version    */

  struct flow* out = (struct flow*)(malloc (sizeof(struct flow)));
  out->ip_src = ip->ip_src;
  out->ip_dst = ip->ip_dst;
  out->timestamp = pkthdr->ts;
  out->last_seen = pkthdr->ts;
  out->route = 0;

  return out;
}


void pcap_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) { 
  u_int16_t type = ethernet_handler(args, pkthdr, packet);

  if (type == ETHERTYPE_IP) {
    long int sec = pkthdr->ts.tv_sec;
    long int usec = pkthdr->ts.tv_usec;
    struct flow* f = flow_handler(args, pkthdr, packet);


    int match = match_flow(f);
    if(match == 1) {
      if(NOISY) fprintf(stdout, "Match forward -- Need to update last_seen for f\n");
      last_seen(f);
      //should update timeout here
    } else if (match == -1) {
      update_count++;
      //Match, so remove from flow table and write out rtt
      struct timeval rtt = rtt_get(f);
      char src_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &f->ip_src, src_str, INET_ADDRSTRLEN);
      char dst_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &f->ip_dst, dst_str, INET_ADDRSTRLEN);
      if(NOISY) fprintf(stdout, "%15s->%15s RTT: %ld.%ld\n",src_str, dst_str, rtt.tv_sec, rtt.tv_usec);

      //add rtt
      update_route(rtt.tv_sec, rtt.tv_usec, &f->ip_dst);


      free(f);
    } else {
      //No match, so add to flow table
      insert_flow(f);
    }

    if(update_count==5) {
      update_count=0;
      print_rib();
    }
  }
}
