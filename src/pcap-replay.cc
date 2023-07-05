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

static int use_rmapw  = 0;
static int use_rmapwrt_rpl = 0;

static struct option long_options[] = {
  {"after",         required_argument, NULL, 'a'},
  {"config",        required_argument, NULL, 'c'},
  {"channel",       required_argument, NULL, 'n'},
  {"interval",      required_argument, NULL, 'i'},
  {"original-time",       no_argument, NULL, 'o'},
  {"receive-reply", required_argument, NULL, 'r'},
  { NULL,                           0, NULL,  0 }
};

static double      param_wait_time     =  0.0;
static double      param_interval_sec  = -1.0;
static std::string param_config        =  ""; 
static std::string param_channel       =  ""; 
static std::string param_replyfile     =  ""; 
static int         param_original_time =  0;

FILE *rp = NULL;

#define PROGNAME "pcap-replay: "

int main(int argc, char *argv[])
{
  pcapnc_unset_stdbuf();

  //// parse options
  
  int option_error = 0;
  
  while (1) {

    int option_index = 0;
    const int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

    if ( c == -1 ) break;
    
    switch (c) {
    case 'a': param_wait_time        = atof(optarg); if (param_wait_time    < 0.0) param_wait_time    = 0.0; break;
    case 'c': param_config    = std::string(optarg); break;
    case 'n': param_channel   = std::string(optarg); break;
    case 'i': param_interval_sec     = atof(optarg); if (param_interval_sec < 0.0) param_interval_sec = 0.0; break;
    case 'o': param_original_time    = 1; break;
    case 'r': param_replyfile = std::string(optarg); break;
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

  pcap_file lp;
  if ( param_replyfile != ""  ){
    const int r_ret = lp.read_head(param_replyfile.c_str()); if ( r_ret ) return r_ret;
    use_rmapwrt_rpl = 1;
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
    ret = ip.read(inbuf, 1, PACKET_HEADER_SIZE);
//// fprintf(stderr," end\n");
    if        ( ret == 0 ) {
      // pcapnc_logerr(PROGNAME "End of file.\n");
      return 0;
    } else if ( ret < PACKET_HEADER_SIZE ) {
      pcapnc_logerr(PROGNAME "Unexpected end of file (partial packet header).\n");
      return ERROR_5;
    }
    const uint32_t coarse_time = ip.extract_uint32(inbuf+ 0);
    const uint32_t fine_time   = ip.extract_uint32(inbuf+ 4);
    const uint32_t caplen      = ip.extract_uint32(inbuf+ 8);
//  const uint32_t orglen      = ip.extract_uint32(inbuf+12);

    double curr_time = coarse_time + fine_time * ip.finetime_unit;

    if ( caplen > PACKET_DATA_MAX_SIZE ) {
      pcapnc_logerr(PROGNAME "Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", caplen);
      return ERROR_6;
    }
    
    ret = ip.read(&(inbuf[PACKET_HEADER_SIZE]), 1, caplen);
    if ( ret < caplen ) {
      pcapnc_logerr(PROGNAME "Unexpected end of file (partial packet data).\n");
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

    if ( use_rmapwrt_rpl ) {

      ret = lp.read(inbuf, 1, PACKET_HEADER_SIZE);
      if        ( ret == 0 ) {
        // pcapnc_logerr(PROGNAME "End of input.\n");
        return 0;
      } else if ( ret < PACKET_HEADER_SIZE ) {
        pcapnc_logerr(PROGNAME "Unexpected end of input (partial packet header).\n");
        return ERROR_5;
      }

  //  const uint32_t coarse_time = lp.extract_uint32(inbuf+ 0);
  //  const uint32_t fine_time   = lp.extract_uint32(inbuf+ 4);
      const uint32_t caplen      = lp.extract_uint32(inbuf+ 8);
  //  const uint32_t orglen      = lp.extract_uint32(inbuf+12);

      if ( caplen > PACKET_DATA_MAX_SIZE ) {
        pcapnc_logerr(PROGNAME "Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", caplen);
        return ERROR_6;
      }

      ret = lp.read(&(inbuf[PACKET_HEADER_SIZE]), 1, caplen);
      if ( ret < caplen ) {
        pcapnc_logerr(PROGNAME "Unexpected end of input (partial packet data).\n");
        return ERROR_7;
      }

      // simulate network

      const size_t num_path_address = rmap_num_path_address(inbuf + PACKET_HEADER_SIZE, caplen);
      const uint8_t *retnbuf = inbuf + PACKET_HEADER_SIZE + num_path_address; 
      size_t retnlen = ((size_t) caplen) - num_path_address;

      // check returned packet is expected

      rmapw.recv_reply(retnbuf, retnlen);
    }

    prev_time = curr_time;
  }
  
  debug_fprintf(stderr, "ret=%zd\n", ret);
  
  return 0;
}
