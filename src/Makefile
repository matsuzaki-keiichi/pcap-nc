ALL=pcap-nc pcap-store pcap-replay 

all: ${ALL}

pcap-nc: pcap-nc.bash
	cp $< $@

pcap-store: pcap-store.bash
	cp $< $@

pcap-replay: pcap-replay.c
	cc -o $@ $^ -lm

install: all
	cp ${ALL} head.pcap ../bin

dist-clean: clean
	rm -f ../bin/*
	
clean:
	rm -f *~ ${ALL}

