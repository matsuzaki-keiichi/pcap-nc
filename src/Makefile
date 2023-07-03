ALL=pcap-nc pcap-store pcap-replay head-diosatlm.pcap head-spp.pcap head-spw.pcap rmap-write
MED=write_head

all: ${ALL} ${MED}

pcap-nc: pcap-nc.bash
	cp $< $@

pcap-store: pcap-store.bash
	cp $< $@

pcap-replay: pcap-replay.cc pcap-nc-util.c s3sim.c rmap_channel.cc rmap_channel.h
	c++ -I rapidjson/include -o $@ $^ -lm

rmap-write: rmap-write.c pcap-nc-util.c s3sim.c 
	cc -o $@ $^ -lm

write_head: write_head.c
	cc -o $@ $^

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

