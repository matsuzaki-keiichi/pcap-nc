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
  pcapnc_unset_stdbuf();

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
  static uint8_t outpt_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];
  size_t         outpt_len;

#if 0
  static uint8_t output_pcap_header[PCAP_HEADER_SIZE] = {
    0xA1, 0xB2, 0x3C, 0x4D, // Magic Number Nano Sec
    0x00, 0x02, 0x00, 0x04, // Major Version, Minor Version
    0x00, 0x00, 0x00, 0x09, // Time Zone
    0x00, 0x00, 0x00, 0x00, // Sigfig
    0x00, 0x01, 0x00, 0x12, // Scap Len
    0x00, 0x00, 0x00, 0x95  // Link Type (0x95=149: DLT_USER2 = SpaceWire)
  };
#endif

  ssize_t ret;

  ////

  pcap_file ip;

  const int i_ret = ip.read_nohead(stdin); if ( i_ret ) return i_ret;

  ////

  class rmap_channel rmapc;
  if ( use_rmap_channel ) {
    rmapc.read_json(param_config.c_str(), param_channel.c_str());
  }

#if 0
  uint8_t linktype;
  if ( use_rmap_channel && rmapc.has_responces() ) {
    linktype = 0x95; // SpaceWire
  } else {
    linktype = 0x94; // SpacePacket
  }
  output_pcap_header[23] = linktype;

  ret = pcapnc_fwrite(output_pcap_header, 1, PCAP_HEADER_SIZE, stdout);
  if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr(PROGNAME "Write Error (PCAP Header).\n");
    return ERROR_5;
  }
#endif  

  while(1){
    ret = ip.read_packet_header(input_buf, sizeof(input_buf), PROGNAME, "input"); if ( ret > 0 ) return ret; if ( ret < 0 ) return 0;
    ret = ip.read_packet_data(input_buf, PROGNAME, "input"); if ( ret > 0 ) return ret;

    if ( !use_rmap_channel ) {
      ret = pcapnc_fwrite(input_buf,  1, PACKET_HEADER_SIZE+ip.caplen, stdout);
    } else {

      // simulate network
      const size_t num_path_address = rmap_num_path_address(input_buf + PACKET_HEADER_SIZE, ip.caplen);
      const uint8_t *rcvbuf = input_buf + PACKET_HEADER_SIZE + num_path_address; 
      size_t rcvlen = ((size_t) ip.caplen) - num_path_address;
      size_t outlen;

      // generate output
      if ( rmapc.has_responces() ) {
        uint8_t rplbuf[999]; 
        size_t  rpllen = sizeof(rplbuf);

        if ( !use_rmaprd_rpl ) {
          // generate RMAP Write Reply
          rmapc.generate_write_reply(rcvbuf, rcvlen, rplbuf, rpllen);
        } else {
          // generate RMAP READ Reply
          uint8_t inpu2_buf[999];
          
          ret = lp.read_packet_header(inpu2_buf, sizeof(inpu2_buf), PROGNAME, "input"); if ( ret > 0 ) return ret; if ( ret < 0 ) return 0;
          ret = lp.read_packet_data(inpu2_buf, PROGNAME, "input"); if ( ret > 0 ) return ret;
          uint8_t *inpbuf  = inpu2_buf  + PACKET_HEADER_SIZE;
          const size_t inplen = lp.caplen;

          rmapc.generate_read_reply(inpbuf, inplen, rcvbuf, rcvlen, rplbuf, rpllen);
        }
        memcpy(outpt_buf+PACKET_HEADER_SIZE, rplbuf, rpllen);
        outlen = rpllen;

        pcapnc_network_encode_uint32(outpt_buf+ 0, ip.coarse_time);
        pcapnc_network_encode_uint32(outpt_buf+ 4, ip.nanosec);
        pcapnc_network_encode_uint32(outpt_buf+ 8, outlen);
        pcapnc_network_encode_uint32(outpt_buf+12, outlen);

        outpt_len = PACKET_HEADER_SIZE + outlen;
        ret = pcapnc_fwrite(outpt_buf, 1, outpt_len, stdout);
        // TODO implement error check
      }

      // reuse outpt_buf

      if ( rmapc.is_write_channel() && store_rmap_write ){

        const uint8_t *outbuf; 

        rmapc.validate_command(rcvbuf, rcvlen, outbuf, outlen); // extract Service Data Unit (e.g. Space Packet)
        memcpy(outpt_buf+PACKET_HEADER_SIZE, outbuf, outlen);

        pcapnc_network_encode_uint32(outpt_buf+ 0, ip.coarse_time);
        pcapnc_network_encode_uint32(outpt_buf+ 4, ip.nanosec);
        pcapnc_network_encode_uint32(outpt_buf+ 8, outlen);
        pcapnc_network_encode_uint32(outpt_buf+12, outlen);

        outpt_len = PACKET_HEADER_SIZE + outlen;
        ret = sp.write(outpt_buf, outpt_len);
        // TODO implement error check
      } 
    }
  }
  
  return 0;
}
