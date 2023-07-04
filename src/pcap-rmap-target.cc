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

static int use_rmapw = 0;

int main(int argc, char *argv[])
{
  //// parse options
  
  int option_error = 0;
  
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
    use_rmapw = 1;
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
    0x00, 0x00, 0x00, 0x94  // Link Type (0x94=148: DLT_USER0 = Space Packet)
  };

  ssize_t ret;

  ////

  pcap_file ip;

  const int i_ret = ip.read_head(stdin); if ( i_ret ) return i_ret;

  ////

  ret = pcapnc_fwrite(output_pcap_header, 1, PCAP_HEADER_SIZE, stdout);
  if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr("Write Error (PCAP Header).\n");
    return ERROR_5;
  }

  class rmap_write_channel rmapw;
  if ( use_rmapw ) {
    rmapw.read_json(param_config.c_str(), param_channel.c_str());
  }

  while(1){
    ret = pcapnc_fread(inbuf, 1, PACKET_HEADER_SIZE, stdin);
    if ( ret < PACKET_HEADER_SIZE ) {
      pcapnc_logerr("Unexpected end of input (partial packet header).\n");
      return ERROR_6;
    }

    const uint32_t coarse_time = ip.extract_uint32(inbuf+ 0);
    const uint32_t fine_time   = ip.extract_uint32(inbuf+ 4);
    const uint32_t caplen      = ip.extract_uint32(inbuf+ 8);
//  const uint32_t orglen      = ip.extract_uint32(inbuf+12);

    if ( caplen > PACKET_DATA_MAX_SIZE ) {
      pcapnc_logerr("Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", caplen);
      return ERROR_7;
    }
    
    ret = pcapnc_fread(&(inbuf[PACKET_HEADER_SIZE]), 1, caplen, stdin);
    if ( ret < caplen ) {
      pcapnc_logerr("Unexpected end of file (partial packet data).\n");
      return ERROR_8;
    }

    if ( use_rmapw ) {
      // simulate network
      const size_t num_path_address = rmap_num_path_address(inbuf + PACKET_HEADER_SIZE, caplen);
      const uint8_t *in_packet = inbuf + PACKET_HEADER_SIZE + num_path_address; 
      size_t inlen = ((size_t) caplen) - num_path_address;

      // generate output
      const uint8_t *out_packet; 
      size_t outlen;

      rmapw.recv(in_packet, inlen, &out_packet, &outlen);
      memcpy(outbuf+PACKET_HEADER_SIZE, out_packet, outlen);

      pcapnc_network_encode_uint32(outbuf+ 0, coarse_time);
      pcapnc_network_encode_uint32(outbuf+ 4, fine_time);
      pcapnc_network_encode_uint32(outbuf+ 8, outlen);
      pcapnc_network_encode_uint32(outbuf+12, outlen);

      ret = pcapnc_fwrite(outbuf, 1, PACKET_HEADER_SIZE+outlen, stdout);
    } else {
      ret = pcapnc_fwrite(inbuf,  1, PACKET_HEADER_SIZE+caplen, stdout);
    }
  }
  
  return 0;
}
