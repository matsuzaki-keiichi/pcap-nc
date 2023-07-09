pcap-nc
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

pcap-store
Arguments:
--link-type: (mandatory)
  either spp (Space Packet Protocol), spw (SpaceWire), and diosatlm (DIOSA Telemetry).
Input:
PCAP Packet Records.
Output:
PCAP file.

pcap-replay
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

pcap-rmap-target:
(channel related arguments)
--channel channelname: (mandatory)
  a channel name listed in the cofiguration file
--config filename: (mandatory)
  name of a configuration file
--send-data output(path): (optional; only for RMAP Read channel)
  input data for a RMAP Read Channel in the PCAP file format
--store-data output(path): (optional; only for RMAP Write channel)
  store user data collected by RMAP Write Transactions in the PCAP format
Input:
RMAP Command Packets in PCAP Packet Records.
Output:
RMAP Reply Packets in PCAP Packet Records.
Retval:
0: success
1: parameter error
2: runtmie error
