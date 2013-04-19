

all: flowtimer

flowtimer: flowtimer.c flowtimer.h flowtimer_pcap.c flowtimer_pcap.h flow.c flow.h rib.c flowtimer_probe.c flowtimer_probe.h
	gcc -pg -g flowtimer.c flowtimer_pcap.c flowtimer_probe.c flow.c rib.c -lpcap --std=c99 -o flowtimer -pg

test: flowtimer
	sudo ./flowtimer en1

clean:
	rm -f flowtimer mping

ping: ping.c
	gcc -Wall --std=c99 ping.c -o ping 
