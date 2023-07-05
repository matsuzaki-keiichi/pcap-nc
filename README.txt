pcap-nc
Arguments:
The combination of the argements for pcap-replay, pcap-store and those for nc and the following:
--sleep second(int) :
  delay time to start nc command
--no-stdin
  no input from stdin, which means pcap-replay is not invoked.

pcap-replay
Arguments:
--after wait_sec(double) :
  time to be wait for sending the first Packet Record.
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
  receive reply from the input and check the reply

pcap-store
Arguments:
--link-type:
  either spp (Space Packet Protocol), spw (SpaceWire), and diosatlm (DIOSA Telemetry).

