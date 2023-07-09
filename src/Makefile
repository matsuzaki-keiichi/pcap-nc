ALL=pcap-nc pcap-store pcap-replay head-diosatlm.pcap head-spp.pcap head-spw.pcap pcap-rmap-target
MED=write_head test-rmap pcapnc.o rmap_channel.o

all: ${ALL} ${MED}

pcap-nc: pcap-nc.bash
	cp $< $@

pcap-store: pcap-store.bash
	cp $< $@

pcap-replay: pcap-replay.cc s3sim.c pcapnc.o rmap_channel.o
	c++ -Wall -I rapidjson/include -o $@ $^ -lm

pcap-rmap-target: pcap-rmap-target.cc s3sim.c pcapnc.o rmap_channel.o
	c++ -Wall -I rapidjson/include -o $@ $^

test-rmap: test-rmap.cc rmap_channel.o	
	c++ -I rapidjson/include -o $@ $^

write_head: write_head.c
	cc -o $@ $^

pcapnc.o: pcapnc.cc 	
	c++ -c $^

rmap_channel.o: rmap_channel.cc 	
	c++ -I rapidjson/include -c $^

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
	rm -f *~ ${ALL} ${MED} *.o


