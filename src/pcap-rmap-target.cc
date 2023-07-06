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

static struct option long_options[] = {
  {"config",   required_argument, NULL, 'c'},
  {"channel",  required_argument, NULL, 'n'},
  { NULL,      0,                 NULL,  0 }
};

static std::string param_config  = ""; 
static std::string param_channel = ""; 

static int use_rmap_channel = 0;

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
    case 'c': param_config  = std::string(optarg); break;
    case 'n': param_channel = std::string(optarg); break;
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

  ////
    
  static uint8_t inbuf  [PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];
  static uint8_t outbuf [PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  static uint8_t output_pcap_header[PCAP_HEADER_SIZE] = {
    0xA1, 0xB2, 0x3C, 0x4D, // Magic Number Nano Sec
    0x00, 0x02, 0x00, 0x04, // Major Version, Minor Version
    0x00, 0x00, 0x00, 0x09, // Time Zone
    0x00, 0x00, 0x00, 0x00, // Sigfig
    0x00, 0x01, 0x00, 0x12, // Scap Len
    0x00, 0x00, 0x00, 0x95  // Link Type (0x95=149: DLT_USER2 = SpaceWire)
  };

  ssize_t ret;

  ////

  pcap_file ip;

  const int i_ret = ip.read_head(stdin); if ( i_ret ) return i_ret;

  ////

  class rmap_write_channel rmapw;
  if ( use_rmap_channel ) {
    rmapw.read_json(param_config.c_str(), param_channel.c_str());
  }

  uint8_t linktype;
  if ( use_rmap_channel && rmapw.has_responces() ) {
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

  while(1){
    ret = ip.read_packet_header(inbuf, sizeof(inbuf), PROGNAME, "input"); if ( ret > 0 ) return ret; if ( ret < 0 ) return 0;
    ret = ip.read_packet_data(inbuf, PROGNAME, "input"); if ( ret > 0 ) return ret;

    if ( !use_rmap_channel ) {
      ret = pcapnc_fwrite(inbuf,  1, PACKET_HEADER_SIZE+ip.caplen, stdout);
    } else {

      // simulate network
      const size_t num_path_address = rmap_num_path_address(inbuf + PACKET_HEADER_SIZE, ip.caplen);
      const uint8_t *in_packet = inbuf + PACKET_HEADER_SIZE + num_path_address; 
      size_t inlen = ((size_t) ip.caplen) - num_path_address;
      size_t outlen;

      // generate output
      if ( rmapw.has_responces() ) {
        uint8_t  replybuf[20]; outlen = 20;

        rmapw.generate_write_reply(in_packet, inlen, replybuf, &outlen); // generate RMAP Write Reply
        memcpy(outbuf+PACKET_HEADER_SIZE, replybuf, outlen);

      } else {
        const uint8_t *out_packet; 

        rmapw.recv(in_packet, inlen, &out_packet, &outlen); // extract Service Data Unit (e.g. Space Packet)
        memcpy(outbuf+PACKET_HEADER_SIZE, out_packet, outlen);
      } 

      pcapnc_network_encode_uint32(outbuf+ 0, ip.coarse_time);
      pcapnc_network_encode_uint32(outbuf+ 4, ip.nanosec);
      pcapnc_network_encode_uint32(outbuf+ 8, outlen);
      pcapnc_network_encode_uint32(outbuf+12, outlen);

      ret = pcapnc_fwrite(outbuf, 1, PACKET_HEADER_SIZE+outlen, stdout);
    }
  }
  
  return 0;
}
