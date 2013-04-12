#include "flowtimer_pcap.h"
#include "flow.h"



u_int16_t ethernet_handler (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  u_int caplen = pkthdr->caplen; /* length of portion present from bpf  */
  u_int length = pkthdr->len;    /* length of this packet off the wire  */
  struct ether_header *eptr;     /* net/ethernet.h                      */
  u_short ether_type;            /* the type of packet (we return this) */
  eptr = (struct ether_header *) packet;
  ether_type = ntohs(eptr->ether_type);

  if(NOISY) {
    fprintf(stdout,"eth: ");
    fprintf(stdout, "%s ",ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout, "%s ",ether_ntoa((struct ether_addr*)eptr->ether_dhost));
  }

  if (ether_type == ETHERTYPE_IP) {
    if(NOISY) {fprintf(stdout,"(ip)");}
  }
 
  if(NOISY) {fprintf(stdout," %d\n",length);} /* print len */
 
  return ether_type;
}

u_char* ip_handler (u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet) {
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

  off = ntohs(ip->ip_off);
  
  fprintf(stdout,"IPH %s:%u->%s:%u ",inet_ntoa(ip->ip_src), tcp->th_sport,inet_ntoa(ip->ip_dst), tcp->th_dport);
  if(NOISY) {
    fprintf(stdout,"tos %u len %u off %u ttl %u prot %u cksum %u ", ip->ip_tos, len, off, ip->ip_ttl,ip->ip_p, ip->ip_sum);

    fprintf(stdout,"seq %u ack %u win %u ", tcp->th_seq, tcp->th_ack, tcp->th_win);
  }
  printf("\n");

  return NULL;
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
    /*if(match == 1) {
      //fprintf(stdout, "Match forward\n");
    } else*/ if (match == -1) {
      //Match, so remove from flow table and write out rtt
      //fprintf(stdout, "Match reverse\n");
      struct timeval rtt = rtt_get(f);
      char src_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &f->ip_src, src_str, INET_ADDRSTRLEN);
      char dst_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &f->ip_dst, dst_str, INET_ADDRSTRLEN);

      fprintf(stdout, "%15s->%15s RTT: %ld.%ld\n",src_str, dst_str, rtt.tv_sec, rtt.tv_usec);
      free(f);
    } else {
      //No match, so add to flow table
      insert_flow(f);
    }
  }
}
