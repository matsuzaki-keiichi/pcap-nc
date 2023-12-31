#include <getopt.h>
#include <string>

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
// PRIx32

#include "rmap_channel.h"
#include "pcapnc.h"

static int store_rmap_write = 0;
static int use_rmaprd_rpl   = 0;

static std::string param_config         = ""; 
static std::string param_channel        = ""; 
static std::string param_send_filename  = ""; 
static std::string param_store_filename = ""; 

#define OPTSTRING ""

static struct option long_options[] = {
  {"config",     required_argument, NULL, 'c'},
  {"channel",    required_argument, NULL, 'n'},
  {"send-data",  required_argument, NULL, 's'},
  {"store-data", required_argument, NULL, 't'},
  { NULL,        0,                 NULL,  0 }
};

#define PROGNAME "pcap-rmap-target: "

#define ERROR_OPT 1
#define ERROR_RUN 2

int pcap_rmapr_send(class rmap_channel &rmapc, pcapnc &ip, pcapnc &op, const uint8_t inpbuf[], size_t  inplen)
{
  int ret;

  static uint8_t cmdbuf[PACKET_DATA_MAX_SIZE];
  size_t         cmdlen = sizeof(cmdbuf);
  ret = ip.read_packet(cmdbuf, cmdlen); // 0:success, -1:end of input, or ERROR_LOG_FATAL 
  if ( ret < 0 ) return -1; // end of input, withouog logging message
  if ( ret > 0 ) return ERROR_RUN; 

  // simulate network
  const uint8_t *rcvbuf = cmdbuf;
  size_t         rcvlen = ip._caplen;
  rmap_channel::remove_path_address(rcvbuf, rcvlen);

  uint8_t rplbuf[PACKET_DATA_MAX_SIZE]; 
  size_t  rpllen = sizeof(rplbuf);

  // generate RMAP READ Reply
  ret = 
  rmapc.generate_read_reply(inpbuf, inplen, rcvbuf, rcvlen, rplbuf, rpllen); // 0:success or ERROR_LOG_FATAL.
  if ( ret != 0 ) return ERROR_RUN;      

  ret = op.write_packet(rplbuf, rpllen); // 0:success or ERROR_LOG_FATAL.
  if ( ret != 0 ) return ERROR_RUN;

  return 0;
}

int pcap_rmapw_recv(class rmap_channel &rmapc, pcapnc &ip, pcapnc &op, uint8_t *&outbuf, size_t &outlen)
{
  int ret;

  static uint8_t *cmdbuf = outbuf;
  size_t          cmdlen = outlen;
  ret = ip.read_packet(cmdbuf, cmdlen); // 0:success, -1:end of input, or ERROR_LOG_FATAL 
  if ( ret < 0 ) return -1; // end of input, withouog logging message
  if ( ret > 0 ) return ERROR_RUN; 

  // simulate network
  const uint8_t *rcvbuf = cmdbuf;
  size_t         rcvlen = ip._caplen;
  rmap_channel::remove_path_address(rcvbuf, rcvlen);

  // generate output
  if ( rmapc.has_responces() ) {
    uint8_t rplbuf[PACKET_DATA_MAX_SIZE]; 
    size_t  rpllen = sizeof(rplbuf);

    // generate RMAP Write Reply
    rmapc.generate_write_reply(rcvbuf, rcvlen, rplbuf, rpllen);

    ret = op.write_packet(rplbuf, rpllen); // 0:success or ERROR_LOG_FATAL.
    if ( ret != 0 ) return ERROR_RUN;
  }

  const uint8_t *tmpbuf;
  rmapc.validate_command(rcvbuf, rcvlen, tmpbuf, outlen); // extract Service Data Unit (e.g. Space Packet)
  outbuf = (/*non const*/ uint8_t *) tmpbuf;

  return 0;
}



int main(int argc, char *argv[])
{
  pcapnc::init_class(argv[0]);

  //// parse options
  
  int option_error = 0;
  while (1) {

    int option_index = 0;
    const int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

    if ( c == -1 ) break;
    
    switch (c) {
    case 'c': param_config         = std::string(optarg); break;
    case 'n': param_channel        = std::string(optarg); break;
    case 's': param_send_filename  = std::string(optarg); break;
    case 't': param_store_filename = std::string(optarg); break;
    default: option_error=1; break;
    }
  }
  if (option_error) return ERROR_OPT;
  
  if ( param_config == "" ){
    pcapnc_logerr(PROGNAME "option '--config' is mandatory.\n");
    return ERROR_OPT;
  } 
  if ( param_channel == "" ){
    pcapnc_logerr(PROGNAME "option '--channel' is mandatory.\n");
    return ERROR_OPT;
  }

  class rmap_channel rmapc;
  const char* config_str  = param_config.c_str();
  const char* channel_str = param_channel.c_str();
  int ret = rmapc.read_json(config_str, channel_str);
  if ( ret != 0 ){
    if        ( ret == rmap_channel::NOFILE ){
      pcapnc_logerr(PROGNAME "configuration file '%s' is not found\n", config_str);
    } else if ( ret == rmap_channel::JSON_ERROR ){
      pcapnc_logerr(PROGNAME "parse error in configuration file '%s'\n", config_str);
    } else {        // rmap_channel::NOCHANNEL
      pcapnc_logerr(PROGNAME "channel '%s' is not found\n", channel_str );
    }
    return ERROR_OPT;
  }

  pcapnc lp(0, "send data");
  if ( param_send_filename != ""  ){
    if ( rmapc.is_write_channel() ) {
      pcapnc_logerr(PROGNAME "option '--send-data' could not be specified for RMAP Write channel '%s'.\n",  channel_str);
      return ERROR_OPT;      
    }
    const char *filename = param_send_filename.c_str();
    const int r_ret = lp.read_head(filename); // 0:success, ERROR_PARAM, ERROR_LOG_FATAL, or ERROR_LOG_WARN.
    if ( r_ret ) {
      pcapnc_logerr(PROGNAME "file '%s' to send data could not be opend.\n",  filename);
      return ERROR_OPT;      
    }
    use_rmaprd_rpl = 1;
  }

  pcapnc sp(0, "store_data");
  if ( param_store_filename != ""  ){
    if ( rmapc.is_read_channel() ) {
      pcapnc_logerr(PROGNAME "option '--store-data' could not be specified for RMAP Read channel '%s'.\n",  channel_str);
      return ERROR_OPT;      
    }
    const char *filename = param_store_filename.c_str();
    const uint8_t linktype = 0x94; // Assume SpacePacket
    const int r_ret = sp.write_head(filename, linktype); // 0:success, ERROR_PARAM, ERROR_LOG_FATAL, or ERROR_LOG_WARN.
    if ( r_ret ) {
      pcapnc_logerr(PROGNAME "file '%s' to store data could not be opend.\n",  filename);
      return ERROR_OPT;
    }
    store_rmap_write = 1;
  }

  //// setup input/output files

  pcapnc ip(1, "input");  const int i_ret = ip.read_nohead(stdin);   // 0:success or ERROR_LOG_WARN.
  if ( i_ret != 0 ) return ERROR_OPT;
  pcapnc op(0, "output"); const int o_ret = op.write_nohead(stdout); // 0:success or ERROR_LOG_WARN.
  if ( o_ret != 0 ) return ERROR_OPT;

  ////
    

  while(1){
    ssize_t ret;

    static uint8_t inpbuf[PACKET_DATA_MAX_SIZE];
    if ( use_rmaprd_rpl ) {
      // generate RMAP READ Reply
        
      ret = lp.read_packet(inpbuf, sizeof(inpbuf)); // 0:success, -1:end of input, or ERROR_LOG_FATAL
      if ( ret <  0 ) return 0; // end of input, withouog logging message
      if ( ret >  0 ) return ERROR_RUN; 
      const size_t inplen = lp._caplen;

      int ret = pcap_rmapr_send(rmapc, ip, op, inpbuf, inplen);
      if ( ret <  0 ) return 0; // end of input, withouog logging message
      if ( ret >  0 ) return ERROR_RUN; 

    } else {

      // not only rmap_write_channek but also rmap_read_channel may here ... 

      uint8_t *outbuf = inpbuf; 
      size_t   outlen = sizeof(inpbuf);
      int ret = pcap_rmapw_recv(rmapc, ip, op, outbuf, outlen);
      if ( ret <  0 ) return 0; // end of input, withouog logging message
      if ( ret >  0 ) return ERROR_RUN; 

      if ( rmapc.is_write_channel() && store_rmap_write ){
        ret = sp.write_packet(outbuf, outlen); // 0:success or ERROR_LOG_FATAL.
        if ( ret != 0 ) return ERROR_RUN;
      }
    }

#if 0
    // simulate network
    const uint8_t *rcvbuf = inpbuf;
    size_t         rcvlen = (size_t) ip._caplen;
    rmap_channel::remove_path_address(rcvbuf, rcvlen);

    // generate output
    if ( rmapc.has_responces() ) {
      uint8_t rplbuf[999]; 
      size_t  rpllen = sizeof(rplbuf);

      if ( !use_rmaprd_rpl ) {
        // generate RMAP Write Reply
        rmapc.generate_write_reply(rcvbuf, rcvlen, rplbuf, rpllen);
      } else {
        // generate RMAP READ Reply
        static uint8_t in2buf[PACKET_DATA_MAX_SIZE];
        
        ret = lp.read_packet(in2buf, sizeof(in2buf)); // 0:success, -1:end of input, or ERROR_LOG_FATAL
        if ( ret <  0 ) return 0; // end of input, withouog logging message
        if ( ret >  0 ) return ERROR_RUN; 
        const size_t in2len = lp._caplen;

        ret = 
        rmapc.generate_read_reply(in2buf, in2len, rcvbuf, rcvlen, rplbuf, rpllen); // 0:success or ERROR_LOG_FATAL.
        if ( ret != 0 ) return ERROR_RUN;      
      }
      ret = op.write_packet(rplbuf, rpllen); // 0:success or ERROR_LOG_FATAL.
      if ( ret != 0 ) return ERROR_RUN;
    }

    if ( rmapc.is_write_channel() && store_rmap_write ){
      const uint8_t *outbuf; 
      size_t outlen;
      rmapc.validate_command(rcvbuf, rcvlen, outbuf, outlen); // extract Service Data Unit (e.g. Space Packet)
      ret = sp.write_packet(outbuf, outlen); // 0:success or ERROR_LOG_FATAL.
      if ( ret != 0 ) return ERROR_RUN;
    } 
#endif
  }
  
  return 0;
}
