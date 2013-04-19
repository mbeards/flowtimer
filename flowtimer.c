#include "flowtimer.h"
#include "flowtimer_pcap.h"
#include "flow.h"

//Filter so we're only looking at unicast packets
char filter_exp[] = "(not ip multicast) and (not ip broadcast) and (not ether multicast) and (not ether broadcast) and (tcp)";

int main(int argc,char **argv) { 
  int i; 
  char *dev; 
  char errbuf[PCAP_ERRBUF_SIZE]; 
  pcap_t* descr; 
  const u_char *packet; 
  struct pcap_pkthdr hdr; /* pcap.h */ 
  struct ether_header *eptr; /* net/ethernet.h */ 
  bpf_u_int32 maskp; /* subnet mask */ 
  bpf_u_int32 netp; /* ip */ 
  struct bpf_program fp;
  
  LIST_INIT(&route_head);
  LIST_INIT(&flow_head);

  dev = "en1";
  endcount = 10000;

  printf("Listen on %s\n", dev);

 
  /* ask pcap for the network address and mask of the device */ 
  pcap_lookupnet(dev,&netp,&maskp,errbuf); 
  /* open device for reading this time lets set it in promiscuous 
  * mode so we can monitor traffic to another machine */ 
  descr = pcap_open_live(dev,BUFSIZ,1,1,errbuf); 
  if(descr == NULL) { 
    printf("pcap_open_live(): %s\n",errbuf);
    exit(1);
  } 
  
  if (pcap_compile(descr, &fp, filter_exp, 0, netp) == -1) {
     fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
     return(2);
  }

  if (pcap_setfilter(descr, &fp) == -1) {
     fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
     return(2);
  }


  update_count = 0;
  
/* ... and loop */ 
  int out = pcap_loop(descr,PACKET_COUNT,pcap_callback,NULL); 
  return 0; 
} 
