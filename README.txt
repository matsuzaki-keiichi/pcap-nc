pcap-nc
Arguments:
The combination of the argements for pcap-replay(*1), pcap-store and those for nc and the following:
--sleep second(int) :
  delay time to start nc command
--no-stdin
  no input from stdin, which means pcap-replay is not invoked.
--check-reply
  check RMAP Write Reply
*1: except for --receive-reply
Input:
PCAP file if --no-stdin is specified. PCAP Packet Records otherwise.
Output:
PCAP file if --link-type is specified. PCAP Packet Records otherwise.

pcap-replay
Arguments:
--before wait_sec(double) :
  time to wait before sending the first Packet Record.
--config filename:
  name of a configuration file
--interval interval_sec (double):
  time interval to be wait for a Packet Record to the next Packet Record.
  Unless specified, time intervals between Packet Records, which is obtained
  from Packet Headers are reproduced by the program
--original-time:
  do not update the values in the timestamp fields of a Packet Record.
  Unless specified, the values in the timestamp fields are updated into the current packet transmission time.
--receive-reply input(path):
  receive reply in the PCAP format from the input and check the reply
--store-data output(path):
  store user data collected by RMAP Read Transactions in the PCAP format
Input:
PCAP file

pcap-store
Arguments:
--link-type:
  either spp (Space Packet Protocol), spw (SpaceWire), and diosatlm (DIOSA Telemetry).
Input:
PCAP Packet Records.
Output:
PCAP file.

pcap-rmap-target:
Input:
PCAP Packet Records.
