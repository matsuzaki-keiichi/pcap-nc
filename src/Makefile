ALL=pcap-nc pcap-store pcap-replay head-diosatlm.pcap head-spp.pcap head-spw.pcap
MED=write_head

all: ${ALL} ${MED}

pcap-nc: pcap-nc.bash
	cp $< $@

pcap-store: pcap-store.bash
	cp $< $@

pcap-replay: pcap-replay.c
	cc -o $@ $^ -lm

write_head: write_head.c
	cc -o $@ $^ -lm

head-diosatlm.pcap:	write_head
	./write_head 147 >$@

head-spp.pcap:	write_head
	./write_head 148 >$@

head-spw.pcap:	write_head
	./write_head 149 >$@

install: all
	mkdir -p ../bin
	cp ${ALL} ../bin

dist-clean: clean
	rm -fr ../bin
	
clean:
	rm -f *~ ${ALL} ${MED}

