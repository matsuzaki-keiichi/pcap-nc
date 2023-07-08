#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
// PRIx32
#include <string.h>
// memcpy
#include <getopt.h>

#include <string>

#include "rmap_channel.h"
#include "pcapnc.h"

#define PACKET_HEADER_SIZE  16
#define PACKET_DATA_MAX_SIZE 0x10006

#define ERROR_5 5
#define ERROR_6 6
#define ERROR_7 7
#define ERROR_8 8

#define OPTSTRING ""

static int store_rmap_write  = 0;

static struct option long_options[] = {
  {"config",     required_argument, NULL, 'c'},
  {"channel",    required_argument, NULL, 'n'},
  {"send-data",  required_argument, NULL, 's'},
  {"store-data", required_argument, NULL, 't'},
  { NULL,        0,                 NULL,  0 }
};

static std::string param_config         = ""; 
static std::string param_channel        = ""; 
static std::string param_send_filename  = ""; 
static std::string param_store_filename = ""; 

static int use_rmaprd_rpl   = 0;

#define PROGNAME "pcap-rmap-target: "

#define ERROR_OPT 1

int main(int argc, char *argv[])
{
  //// parse options
  
  int option_error    = 0;
  
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
  if (option_error) {
    return 1;
  }
  
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

  pcapnc lp;
  if ( param_send_filename != ""  ){
    if ( rmapc.is_write_channel() ) {
      pcapnc_logerr(PROGNAME "option '--send-data' could not be specified for RMAP Write channel '%s'.\n",  channel_str);
      return ERROR_OPT;      
    }
    const char *filename = param_send_filename.c_str();
    const int r_ret = lp.read_head(filename); 
    if ( r_ret ) {
      pcapnc_logerr(PROGNAME "file '%s' to send data could not be opend.\n",  filename);
      return ERROR_OPT;      
    }
    use_rmaprd_rpl = 1;
    // TODO should implement consistency check with this->instruction
  }

  pcapnc sp;
  if ( param_store_filename != ""  ){
    if ( rmapc.is_read_channel() ) {
      pcapnc_logerr(PROGNAME "option '--store-data' could not be specified for RMAP Read channel '%s'.\n",  channel_str);
      return ERROR_OPT;      
    }
    const char *filename = param_store_filename.c_str();
    const uint8_t linktype = 0x94; // Assume SpacePacket
    const int r_ret = sp.write_head(filename, linktype); 
    if ( r_ret ) {
      pcapnc_logerr(PROGNAME "file '%s' to store data could not be opend.\n",  filename);
      return ERROR_OPT;
    }
    store_rmap_write = 1;
  }

  //// setup input/output files

  pcapnc ip; const int i_ret = ip.read_nohead(stdin);   if ( i_ret ) return i_ret;
  pcapnc op; const int o_ret = op.write_nohead(stdout); if ( o_ret ) return o_ret;

  ////
    
  static uint8_t input_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  while(1){
    ssize_t ret;
    ret = ip.read_packet_header(input_buf, sizeof(input_buf), PROGNAME, "input"); if ( ret > 0 ) return ret; if ( ret < 0 ) return 0;
    ret = ip.read_packet_data(input_buf, PROGNAME, "input"); if ( ret > 0 ) return ret;

    // simulate network
    const size_t num_path_address = rmap_num_path_address(input_buf + PACKET_HEADER_SIZE, ip.caplen);
    const uint8_t *rcvbuf = input_buf + PACKET_HEADER_SIZE + num_path_address; 
    size_t rcvlen = ((size_t) ip.caplen) - num_path_address;

    // generate output
    if ( rmapc.has_responces() ) {
      uint8_t rplbuf[999]; 
      size_t  rpllen = sizeof(rplbuf);

      if ( !use_rmaprd_rpl ) {
        // generate RMAP Write Reply
        rmapc.generate_write_reply(rcvbuf, rcvlen, rplbuf, rpllen);
      } else {
        // generate RMAP READ Reply
        static uint8_t inpu2_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];
        
        ret = lp.read_packet_header(inpu2_buf, sizeof(inpu2_buf), PROGNAME, "send data"); if ( ret > 0 ) return ret; if ( ret < 0 ) return 0;
        ret = lp.read_packet_data(inpu2_buf, PROGNAME, "send data"); if ( ret > 0 ) return ret;
        uint8_t     *inpbuf = inpu2_buf  + PACKET_HEADER_SIZE;
        const size_t inplen = lp.caplen;

        rmapc.generate_read_reply(inpbuf, inplen, rcvbuf, rcvlen, rplbuf, rpllen);
      }
      ret = op.write_packet_record(ip.coarse_time, ip.nanosec, rplbuf, rpllen, PROGNAME, "output");
      // TODO implement error check
    }

    if ( rmapc.is_write_channel() && store_rmap_write ){
      const uint8_t *outbuf; 
      size_t outlen;
      rmapc.validate_command(rcvbuf, rcvlen, outbuf, outlen); // extract Service Data Unit (e.g. Space Packet)
      ret = sp.write_packet_record(ip.coarse_time, ip.nanosec, outbuf, outlen, PROGNAME, "store_data");
      // TODO implement error check
    } 
  }
  
  return 0;
}
