#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
// PRIx32
#include <string.h>
// memcpy
#include <getopt.h>

#include <string>

#include "rmap_channel.h"
#include "pcap-nc-util.h"

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

static std::string param_config        = ""; 
static std::string param_channel       = ""; 
static std::string param_send_filename = ""; 
static std::string param_storefile     = ""; 

static int use_rmap_channel = 0;
static int use_rmaprd_rpl   = 0;

#define PROGNAME "pcap-rmap-target: "


int main(int argc, char *argv[])
{
  //// parse options
  
  int option_error    = 0;
  
  while (1) {

    int option_index = 0;
    const int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

    if ( c == -1 ) break;
    
    switch (c) {
    case 'c': param_config        = std::string(optarg); break;
    case 'n': param_channel       = std::string(optarg); break;
    case 's': param_send_filename = std::string(optarg); break;
    case 't': param_storefile     = std::string(optarg); break;
    default: option_error=1; break;
    }
  }
  if (option_error) {
    return 1;
  }
  
  if ( param_config != "" && param_channel != "" ){
    use_rmap_channel = 1;
    // TODO fix tentative implementation.
  }

  //// setup input/output files

  pcap_file ip; const int i_ret = ip.read_nohead(stdin);   if ( i_ret ) return i_ret;
  pcap_file op; const int o_ret = op.write_nohead(stdout); if ( o_ret ) return o_ret;

  pcap_file lp;
  if ( param_send_filename != ""  ){
    const int r_ret = lp.read_head(param_send_filename.c_str()); if ( r_ret ) return r_ret;
    use_rmaprd_rpl = 1;
    // TODO should implement consistency check with this->instruction
  }
  pcap_file sp;
  if ( param_storefile != ""  ){
    const uint8_t linktype = 0x94; // Assume SpacePacket
    const int r_ret = sp.write_head(param_storefile.c_str(), linktype); if ( r_ret ) return r_ret;
    store_rmap_write = 1;
  }

  ////
    
  static uint8_t input_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  ssize_t ret;

  class rmap_channel rmapc;
  if ( use_rmap_channel ) {
    rmapc.read_json(param_config.c_str(), param_channel.c_str());
  }

  while(1){
    ret = ip.read_packet_header(input_buf, sizeof(input_buf), PROGNAME, "input"); if ( ret > 0 ) return ret; if ( ret < 0 ) return 0;
    ret = ip.read_packet_data(input_buf, PROGNAME, "input"); if ( ret > 0 ) return ret;

    if ( !use_rmap_channel ) {
      const size_t input_len = PACKET_HEADER_SIZE+ip.caplen;
      ret = op.write(input_buf, input_len);
    } else {

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
  }
  
  return 0;
}
