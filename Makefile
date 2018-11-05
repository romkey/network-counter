CC=gcc
CFLAGS=-DPCAP_FILE=\"./packets-10000.pcap\"

all: counter counter_report

counter: counter.c counter.h shared_memory.c
	$(CC) $(CFLAGS) -o counter counter.c  shared_memory.c -lpcap

counter_report: counter_report.c counter.h shared_memory.c
	$(CC) -o counter_report counter_report.c shared_memory.c

clean:
	rm *.o counter counter_report
