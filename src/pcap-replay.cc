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

#define OPTSTRING ""

static int use_rmap_channel  = 0;
static int use_rmap_reply = 0;

static struct option long_options[] = {
  {"after",         required_argument, NULL, 'a'},
  {"before",        required_argument, NULL, 'b'},
  {"config",        required_argument, NULL, 'c'},
  {"channel",       required_argument, NULL, 'n'},
  {"interval",      required_argument, NULL, 'i'},
  {"original-time",       no_argument, NULL, 'o'},
  {"receive-reply", required_argument, NULL, 'r'},
  { NULL,                           0, NULL,  0 }
};

static double      param_after_wtime   =  0.0;
static double      param_before_wtime  =  0.0;
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
    case 'a': param_after_wtime      = atof(optarg); if (param_after_wtime  < 0.0) param_after_wtime  = 0.0; break;
    case 'b': param_before_wtime     = atof(optarg); if (param_before_wtime < 0.0) param_before_wtime = 0.0; break;
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
    use_rmap_channel = 1;
    // TODO fix tentative implementation.
  }

  pcap_file lp;
  if ( param_replyfile != ""  ){
    const int r_ret = lp.read_head(param_replyfile.c_str()); if ( r_ret ) return r_ret;
    use_rmap_reply = 1;
  }

  debug_fprintf(stderr, "param_before_wtime=%f\n", param_before_wtime);

  ////
    
  static uint8_t input_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];
  static uint8_t trans_buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  ssize_t ret;

  ////

  pcap_file ip;

  const int i_ret = ip.read_head(stdin); if ( i_ret ) return i_ret;

  ////

  double prev_time = -1;
  
  class rmap_channel rmapc;

  if ( use_rmap_channel ) {
    rmapc.read_json(param_config.c_str(), param_channel.c_str());
  }

//// int i=0;
  while(1){
    ret = ip.read_packet_header(input_buf, sizeof(input_buf), PROGNAME, "file"); 
    if ( ret > 0 ) return ret;                                                                      
    if ( ret < 0 ) { s3sim_sleep(param_after_wtime); return 0; }

    ret = ip.read_packet_data(input_buf, PROGNAME, "file"); 
    if ( ret > 0 ) return ret;

    // generated output (ending conversion is performed if needed)

    if (!param_original_time) {
      struct timeval tv;
      
      const int iret = gettimeofday(&tv, NULL);

      if ( iret == 0 ) {
      	const uint32_t now_coarse_time =          (uint32_t)  tv.tv_sec;
      	const uint32_t now_nanosec     =   1000 * (uint32_t)  tv.tv_usec;	
      	pcapnc_network_encode_uint32(trans_buf+ 0, now_coarse_time);
      	pcapnc_network_encode_uint32(trans_buf+ 4, now_nanosec);
      } else {
        // TODO implement error handling
      }
    } else {
      pcapnc_network_encode_uint32(trans_buf+ 0, ip.coarse_time);
      pcapnc_network_encode_uint32(trans_buf+ 4, ip.nanosec);
    }

    size_t cmdlen;
    uint8_t *inpbuf = input_buf + PACKET_HEADER_SIZE;
    uint8_t *cmdbuf = trans_buf + PACKET_HEADER_SIZE;
    if ( use_rmap_channel ) {

      cmdlen = PACKET_DATA_MAX_SIZE;
      if ( rmapc.is_write_channel() ){
        const size_t inplen  = ip.caplen;
        rmapc.generate_write_command(inpbuf, inplen, cmdbuf, cmdlen);
//fprintf(stderr,"write channel\n");        
      } else {
//fprintf(stderr,"read channel\n");        
        rmapc.generate_read_command(cmdbuf, cmdlen);
      }
    } else {
      memcpy(cmdbuf, inpbuf, ip.caplen);
      cmdlen = ip.caplen;
    }

    pcapnc_network_encode_uint32(trans_buf+ 8, cmdlen);
    pcapnc_network_encode_uint32(trans_buf+12, cmdlen);

    double curr_time = ip.coarse_time + ip.nanosec * 1e-9;
    if ( prev_time < 0 ) {

      s3sim_sleep(param_before_wtime);

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
    prev_time = curr_time;
    debug_fprintf(stderr, "curr_time=%f\n", curr_time);

    ret = pcapnc_fwrite(trans_buf, 1, PACKET_HEADER_SIZE+cmdlen, stdout);

    if ( use_rmap_reply ) {

      ret = lp.read_packet_header(input_buf, sizeof(input_buf), PROGNAME, "input"); 
      if ( ret > 0 ) return ret; 
      if ( ret < 0 ) { s3sim_sleep(param_after_wtime); return 0; }
      ret = lp.read_packet_data(input_buf, PROGNAME, "input"); 
      if ( ret > 0 ) return ret;

      // simulate network

      const size_t num_path_address = rmap_num_path_address(input_buf + PACKET_HEADER_SIZE, lp.caplen);
      const uint8_t *retnbuf = input_buf + PACKET_HEADER_SIZE + num_path_address; 
      size_t retnlen = ((size_t) lp.caplen) - num_path_address;

      // check returned packet is expected

      const uint8_t *outbuf;
      size_t outsize;

      rmapc.validate_reply(retnbuf, retnlen, outbuf, outsize);
    }
  }
  
  debug_fprintf(stderr, "ret=%zd\n", ret);
  
  return 0;
}
