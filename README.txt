pcap-nc

Program to simulate SpaceWire/RMAP trunsactions over TCP/IP network.

Data is stored in files in the PCAP format.

In a socket over TCP/IP communication, 
PCAP Packet Records (without PCAP Header) are transferred.

In the test directory, a sequence of space packets are transfered 
from a client to a server or from a server to a client 
through the following channels:

- Packet Transfer Protocol 
- RMAP Write Channel (without acknowledge)　
- RMAP Write Channel (with acknowledge)
- RMAP Read  Channel

==== How to use ====

cd src

ln -s (path to rapid json directory) rapidjson

make install
make clean

cd ../test
./test-all.sh

==== specification of commands ====

[pcap-nc]
[pcap-replay]
[pcap-rmap-target]
[pcap-store]

[pcap-nc]
Arguments:
The combination of the argements for pcap-replay(*1), pcap-store and those for nc and the following:
--sleep second(int) :
  delay time to start nc command
--no-stdin
  no input from stdin, which means pcap-replay is not invoked.
--check-reply (optional; only for RMAP Read channel or RMAP Write channel with acknowledges)
  check RMAP Write Reply
*1: except for --receive-reply
Input:
PCAP Packet Records if --no-stdin is specified. PCAP file otherwise.
Output:
PCAP Packet Records if --link-type is not specified. PCAP file otherwise.

[pcap-store]
Arguments:
--link-type: (mandatory)
  either spp (Space Packet Protocol), spw (SpaceWire), and diosatlm (DIOSA Telemetry).
Input:
PCAP Packet Records.
Output:
PCAP file.

[pcap-replay]
Arguments:
(time/timing related arguments)
--after wait_sec(double) : (optional)
  time to wait after sending the last Packet Record.
--before wait_sec(double) : (optional)
  time to wait before sending the first Packet Record.
--interval interval_sec (double): (optional)
  time interval to be wait for a Packet Record to the next Packet Record.
  Unless specified, time intervals between Packet Records, which is obtained
  from Packet Headers are reproduced by the program
--original-time: (optional)
  do not update the values in the timestamp fields of a Packet Record.
  Unless specified, the values in the timestamp fields are updated into the current packet transmission time.
(channel related arguments)
--config filename: (optional)
  name of a configuration file
--channel channelname: (optional; requires --config option)
  a RMAP channel name listed in the cofiguration file
--receive-reply input(path): (optional; only for RMAP Read channel or RMAP Write channel with acknowledges)
  receive reply in the PCAP format from the input and check the reply
--store-data output(path): (optional; only for RMAP read channel, requires --receive-reply option)
  store user data collected by RMAP Read Transactions in the PCAP format
--no-spw-on-eth: (optional)
  omit the header for spw-on-eth.
--read-repeated: (optional)
  specifies to transmit read commands internally. 
  This parameter disables input from stdin and cannot be used with '--original-time'.
--num-packet (number(double)): (optional)
  specifies the number of transmitted packets for read-repeated. 
  This parameter must be used with '--read-repeated'.
  Unless this parameter is specified, pcap-replay transmits read commands indefinitely.
Input:
PCAP file
Note: Input is dummy (i.e. only time is used) for a RMAP Read channel. 
Output:
RMAP Command Packets in PCAP Packet Records if RMAP Write/Read Channel is specified.
PCAP Packet Records in the input PCAP file otherwise.
Retval:
0: success
1: parameter error
2: runtmie error

[pcap-rmap-target]
Arguments:
(channel related arguments)
--channel channelname: (mandatory)
  a channel name listed in the cofiguration file
--config filename: (mandatory)
  name of a configuration file
--send-data output(path): (optional; only for RMAP Read channel)
  input data for a RMAP Read Channel in the PCAP file format
  If this parameter is not specified, it branches to the processing of the write command.(memo: TODO JAXA)
--store-data output(path): (optional; only for RMAP Write channel)
  store user data collected by RMAP Write Transactions in the PCAP format
--no-spw-on-eth
  omit the header for spw-on-eth.
--delay
  delays the time information given to the reply packet by the specified number of seconds.
--shared-memory=key:key_name,RemoteBufferAddress:address(in hex)#RemoteBufferSize:size(in dec),DeviceRegisterAddress:address(in hex)
  key_name: the name of a shared memory key (e.g., TEB)
  RemoteBufferAddress: the Remote Buffer Address of a shared memory (e.g., 0x89ABCDEF)
  RemoteBufferSize: the size of a shared memory (e.g., 2048)
  DeviceRegisterAddress: the address used to store flags, write addresses, and the lengths of writes. (e.g., 0x00000000)
  The size of the DeviceRegister is specified in the header file.(shared_mem.h)
  This parameter cannot be used with '--send-data'.(RMAP Read channel)
  This parameter has no restrictions on use with '--store-data'.(RMAP Write channel)



Input:
RMAP Command Packets in PCAP Packet Records.
Output:
RMAP Reply Packets in PCAP Packet Records.
Retval:
0: success
1: parameter error
2: runtmie error


==== configuration ====

.
├── README.txt
├── src
│   ├── head.pcap
│   ├── Implementation.txt
│   ├── Makefile
│   ├── pcap-nc.bash
│   ├── pcapnc.cc
│   ├── pcapnc.h
│   ├── pcap-replay.cc
│   ├── pcap-rmap-target.cc
│   ├── pcap-store.bash
│   ├── rmap_channel.cc
│   ├── rmap_channel.h
│   ├── s3sim.c
│   ├── s3sim.h
│   ├── shared_mem.cc
│   ├── shared_mem.h
│   ├── spw_on_eth_head.cc   # handle spacewire on ethernet
│   ├── spw_on_eth_head.h    # handle spacewire on ethernet
│   ├── test-rmap.cc
│   └── write_head.c
└── test
    ├── errors.json
    ├── expected
    │   ├── test-pcap-replay-options1.log
    │   ├── test-pcap-replay-options2.log
    │   ├── test-pcap-replay-options3.log
    │   ├── test-pcap-replay-options4.log
    │   ├── test-pcap-replay-options5.log
    │   ├── test-pcap-replay-options6.log
    │   ├── test-pcap-replay-options7.log
    │   ├── test-pcap-replay-options8.log
    │   ├── test-pcap-replay-options9.log
    │   ├── test-pcap-replay-readrepeated1.log
    │   ├── test-pcap-replay-readrepeated2.log
    │   ├── test-pcap-replay-readrepeated3.log
    │   ├── test-pcap-replay-readrepeated4.log
    │   ├── test-pcap-replay-readrepeated5.log
    │   ├── test-pcap-rmap-target-delay1.log
    │   ├── test-pcap-rmap-target-delay2.log
    │   ├── test-pcap-rmap-target-options1.log
    │   ├── test-pcap-rmap-target-options2.log
    │   ├── test-pcap-rmap-target-options3.log
    │   ├── test-pcap-rmap-target-options4.log
    │   ├── test-pcap-rmap-target-options5.log
    │   ├── test-pcap-rmap-target-options6.log
    │   ├── test-pcap-rmap-target-options7.log
    │   ├── test-pcap-rmap-target-options8.log
    │   ├── test-pcap-rmap-target-options9.log
    │   ├── test-rmapr-out-nospw.pcap
    │   ├── test-rmapr-out.pcap
    │   ├── test-rmapr-rpl-out-delay.pcap
    │   ├── test-rmapr-rpl-out-nospw.pcap
    │   ├── test-rmapr-rpl-out-num-packet.pcap
    │   ├── test-rmapr-rpl-out.pcap
    │   ├── test-rmapr-rpl-out-shm.pcap
    │   ├── test-rmap-target-shm1.log
    │   ├── test-rmap-target-shm2.log
    │   ├── test-rmap-target-shm3.log
    │   ├── test-rmap-target-shm4.log
    │   ├── test-rmap-target-shm5.log
    │   ├── test-rmap-target-shm6.log
    │   ├── test-rmap-target-shm7.log
    │   ├── test-rmapw-spp-out-nospw.pcap
    │   ├── test-rmapw-spp-out.pcap
    │   ├── test-rpl-out-delay.pcap
    │   ├── test-rpl-out-nospw.pcap
    │   ├── test-rpl-out.pcap
    │   └── test-spp-out.pcap
    ├── head-spw.pcap
    ├── sample.json
    ├── spw.pcap
    ├── test1a-client.sh
    ├── test1b-client.sh
    ├── test1c-client.sh
    ├── test1-client.sh
    ├── test1e-client.sh
    ├── test1-server.sh
    ├── test2-client.sh
    ├── test2-server.sh
    ├── test-all.sh
    ├── testcases.txt
    ├── test-client2server-11-rmapw_nospw.sh
    ├── test-client2server-11-rmapw.sh
    ├── test-client2server-12-rmapw-spp_nospw.sh
    ├── test-client2server-12-rmapw-spp.sh
    ├── test-client2server-13-rmapw-rpl_nospw.sh
    ├── test-client2server-13-rmapw-rpl.sh
    ├── test-client2server-14-rmapw-rpl2_nospw.sh
    ├── test-client2server-14-rmapw-rpl2.sh
    ├── test-client2server-15-rmapw-rpl3_nospw.sh
    ├── test-client2server-15-rmapw-rpl3.sh
    ├── test-client2server-21-rmapr_nospw.sh
    ├── test-client2server-21-rmapr.sh
    ├── test-client2server-22-rmapr-rpl_nospw.sh
    ├── test-client2server-22-rmapr-rpl.sh
    ├── test-client2server-23-rmapr-rpl2_nospw.sh
    ├── test-client2server-23-rmapr-rpl2.sh
    ├── test-client2server-24-rmapr-rpl3_nospw.sh
    ├── test-client2server-24-rmapr-rpl3.sh
    ├── test-client2server-30-rmapw-rpl3.sh
    ├── test-client2server.sh
    ├── test-delay3.sh
    ├── test-delay4.sh
    ├── test-delay5.sh
    ├── test-delay6.sh
    ├── test-delay-all.sh
    ├── test-pcap-replay-options.sh
    ├── test-pcap-rmap-target-options.sh
    ├── test-read-repeated-all.sh
    ├── test-read-repeated-inf.sh
    ├── test-read-repeated.sh
    ├── test-server2client-11-rmapw_nospw.sh
    ├── test-server2client-11-rmapw.sh
    ├── test-server2client-12-rmapw-spp_nospw.sh
    ├── test-server2client-12-rmapw-spp.sh
    ├── test-server2client-13-rmapw-rpl_nospw.sh
    ├── test-server2client-13-rmapw-rpl.sh
    ├── test-server2client-14-rmapw-rpl2_nospw.sh
    ├── test-server2client-14-rmapw-rpl2.sh
    ├── test-server2client-15-rmapw-rpl3_nospw.sh
    ├── test-server2client-15-rmapw-rpl3.sh
    ├── test-server2client-21-rmapr_nospw.sh
    ├── test-server2client-21-rmapr.sh
    ├── test-server2client-22-rmapr-rpl_nospw.sh
    ├── test-server2client-22-rmapr-rpl.sh
    ├── test-server2client-23-rmapr-rpl2_nospw.sh
    ├── test-server2client-23-rmapr-rpl2.sh
    ├── test-server2client-24-rmapr-rpl3_nospw.sh
    ├── test-server2client-24-rmapr-rpl3.sh
    ├── test-server2client-30-rmapw-rpl3.sh
    ├── test-server2client.sh
    ├── test-shm1-1.sh
    ├── test-shm1-2.sh
    ├── test-shm1-3.sh
    ├── test-shm1-4.sh
    ├── test-shm1-5.sh
    ├── test-shm1-6.sh
    ├── test-shm1-7.sh
    ├── test-shm2-1.sh
    ├── test-shm2-2.sh
    ├── test-shm-all.sh
    └── test-spp.pcap

end of file
