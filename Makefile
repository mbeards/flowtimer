

all: flowtimer

flowtimer: flowtimer.c flowtimer.h flowtimer_pcap.c flowtimer_pcap.h flow.c flow.h rib.c
	gcc -g flowtimer.c flowtimer_pcap.c flow.c rib.c -lpcap --std=c99 -o flowtimer

test: flowtimer
	sudo ./flowtimer en1

clean:
	rm -f flowtimer
