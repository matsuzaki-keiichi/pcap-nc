#include <stdio.h>
#include <stdlib.h>
// atof
#include <unistd.h>
// sleep
#include <stdint.h>
#include <string.h>
// memcpy
#include <inttypes.h>
// PRIx32
#include <sys/time.h>
// gettimeofday
#include <byteswap.h>
// bswap_32 (gcc)
#include <getopt.h>

#include <string>

#include "rmap_channel.h"
#include "pcap-nc-util.h"
#include "s3sim.h"

// #define DEBUG

#ifdef DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif

#define PCAP_HEADER_SIZE    24
#define PACKET_HEADER_SIZE  16
#define PACKET_DATA_MAX_SIZE 0x10006

#define MAGIC_NUMBER_USEC   0xA1B2C3D4
#define MAGIC_NUMBER_NSEC   0xA1B23C4D
#define PCAP_MAJOR_VERSION   2
#define PCAP_MINOR_VERSION   4

#define ERROR_1 1
#define ERROR_2 2
#define ERROR_3 3
#define ERROR_4 4
#define ERROR_5 5
#define ERROR_6 6
#define ERROR_7 7

#define OPTSTRING ""

static int use_rmapw = 0;

static struct option long_options[] = {
  {"after",         required_argument, NULL, 'a'},
  {"config",        required_argument, NULL, 'c'},
  {"channel",       required_argument, NULL, 'n'},
  {"interval",      required_argument, NULL, 'i'},
  {"original-time",       no_argument, NULL, 'o'},
  { NULL,      0,                 NULL,  0 }
};

static double      param_wait_time     =  0.0;
static double      param_interval_sec  = -1.0;
static std::string param_config        =  ""; 
static std::string param_channel       =  ""; 
static int         param_original_time =  0;

int main(int argc, char *argv[])
{
  //// parse options
  
  int option_error = 0;
  
  while (1) {

    int option_index = 0;
    const int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

    if ( c == -1 ) break;
    
    switch (c) {
    case 'a': param_wait_time      = atof(optarg); if (param_wait_time    < 0.0) param_wait_time    = 0.0; break;
    case 'c': param_config  = std::string(optarg); break;
    case 'n': param_channel = std::string(optarg); break;
    case 'i': param_interval_sec   = atof(optarg); if (param_interval_sec < 0.0) param_interval_sec = 0.0; break;
    case 'o': param_original_time  = 1; break;
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

  debug_fprintf(stderr, "param_wait_time=%f\n", param_wait_time);

  ////
    
  static uint8_t inbuf  [PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];
  static uint8_t outbuf [PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  ssize_t ret;

  ////

  pcap_file ip;

  const int i_ret = ip.read_head(stdin); if ( i_ret ) return i_ret;

  ////

  double prev_time = -1;
  
  class rmap_write_channel rmapw;

  if ( use_rmapw ) {
    rmapw.read_json(param_config.c_str(), param_channel.c_str());
  }

//// int i=0;
  while(1){
///// fprintf(stderr,"read=%d start", i++);
    ret = pcapnc_fread(inbuf, 1, PACKET_HEADER_SIZE, stdin);
//// fprintf(stderr," end\n");
    if ( ret < PACKET_HEADER_SIZE ) {
      pcapnc_logerr("Unexpected end of file (partial packet header).\n");
      return ERROR_5;
    }
    const uint32_t coarse_time = ip.extract_uint32(inbuf+ 0);
    const uint32_t fine_time   = ip.extract_uint32(inbuf+ 4);
    const uint32_t caplen      = ip.extract_uint32(inbuf+ 8);
//  const uint32_t orglen      = ip.extract_uint32(inbuf+12);

    double curr_time = coarse_time + fine_time * ip.finetime_unit;

    if ( caplen > PACKET_DATA_MAX_SIZE ) {
      pcapnc_logerr("Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", caplen);
      return ERROR_6;
    }
    
    ret = pcapnc_fread(&(inbuf[PACKET_HEADER_SIZE]), 1, caplen, stdin);
    if ( ret < caplen ) {
      pcapnc_logerr("Unexpected end of file (partial packet data).\n");
      return ERROR_7;
    }

    // generated output (ending conversion is performed if needed)

    if (!param_original_time) {
      struct timeval tv;
      
      const int iret = gettimeofday(&tv, NULL);

      if ( iret == 0 ) {
      	const uint32_t now_coarse_time =          (uint32_t)  tv.tv_sec;
      	const uint32_t now_fine_time   = ip.u2p * (uint32_t)  tv.tv_usec;
	
      	pcapnc_network_encode_uint32(outbuf+ 0, now_coarse_time);
      	pcapnc_network_encode_uint32(outbuf+ 4, now_fine_time);
      }
    } else {
      pcapnc_network_encode_uint32(outbuf+ 0, coarse_time);
      pcapnc_network_encode_uint32(outbuf+ 4, fine_time);
    }

    size_t outlen;
    uint8_t *in_packet  = inbuf  + PACKET_HEADER_SIZE;
    uint8_t *out_packet = outbuf + PACKET_HEADER_SIZE;
    if ( use_rmapw ) {
      const size_t insize  = caplen;
      size_t outsize = PACKET_DATA_MAX_SIZE;

      rmapw.send_witouht_ack(in_packet, insize, out_packet, &outsize);

      outlen = outsize;
    } else {
      memcpy(out_packet, in_packet, caplen);
      outlen = caplen;
    }

    pcapnc_network_encode_uint32(outbuf+ 8, outlen);
    pcapnc_network_encode_uint32(outbuf+12, outlen);

    if ( prev_time < 0 ) {

      s3sim_sleep(param_wait_time);

    } else {
      const double tdiff = curr_time - prev_time;

      if        ( param_interval_sec < 0.0 ) {
	      s3sim_sleep(tdiff);
      } else if ( param_interval_sec > 0.0 ) {
      	s3sim_sleep(param_interval_sec);
      } else {
        // do not sleep
      }
    }
    debug_fprintf(stderr, "curr_time=%f\n", curr_time);

    ret = pcapnc_fwrite(outbuf, 1, PACKET_HEADER_SIZE+outlen, stdout);

    prev_time = curr_time;
  }
  
  debug_fprintf(stderr, "ret=%zd\n", ret);
  
  return 0;
}
