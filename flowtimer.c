#include "flowtimer.h"
#include "flowtimer_pcap.h"
#include "flow.h"

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
  
  LIST_INIT(&route_head);
  LIST_INIT(&flow_head);

  dev = "en1";

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


  update_count = 0;
  
/* ... and loop */ 
  int out = pcap_loop(descr,-1,pcap_callback,NULL); 
  return 0; 
} 
