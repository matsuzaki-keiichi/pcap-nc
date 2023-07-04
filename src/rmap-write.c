#include <stdio.h>
#include <stdlib.h>
// atof
#include <unistd.h>
// sleep
#include <stdint.h>
#include <inttypes.h>
// PRIx32
#include <sys/time.h>
// gettimeofday
#include <getopt.h>

#include "pcap-nc-util.h"
#include "s3sim.h"

#define PACKET_HEADER_SIZE  16
#define PACKET_DATA_MAX_SIZE 0x10006

#define WRITE_RETRY 1 // sec

#define ERROR_1 1
#define ERROR_2 2
#define ERROR_3 3
#define ERROR_4 4
#define ERROR_5 5
#define ERROR_6 6
#define ERROR_7 7

// #define DEBUG

#define OPTSTRING ""

static int verbose_flag = 0;

static struct option long_options[] = {
  {"after",         required_argument, NULL, 'a'},
  {"interval",      required_argument, NULL, 'i'},
  { NULL,      0,                 NULL,  0 }
};

static double param_wait_time     = 0.0;
static double param_interval_sec  = 0.0;
static int    param_original_time = 0;

static const uint32_t U2P = 1000;

int main(int argc, char *argv[])
{
  int option_error = 0;
  
  while (1) {

    int option_index = 0;
    const int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

    if ( c == -1 ) break;
    
    switch (c) {
    case 'a': param_wait_time    = atof(optarg); if (param_wait_time    < 0.0) param_wait_time    = 0.0; break;
    case 'i': param_interval_sec = atof(optarg); if (param_interval_sec < 0.0) param_interval_sec = 0.0; break;
    default: option_error=1; break;
    }
  }
  if (option_error) {
    return 1;
  }
  
  debug_fprintf(stderr, "param_wait_time=%u\n", param_wait_time);

  ////
    
  char buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  ssize_t ret;
  
  s3sim_sleep(param_wait_time);

  while(1){
    const uint32_t caplen = 999;
    const uint32_t orglen = 999;

    if ( caplen > PACKET_DATA_MAX_SIZE ) {
      fprintf(stderr, "Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", caplen);
      return ERROR_6;
    }
    
    // update Packet Header (ending conversion is performed if needed)

    struct timeval tv;      
    const int iret = gettimeofday(&tv, NULL);

    uint32_t coarse_time = 0;
    uint32_t fine_time   = 0;

    if ( iret == 0 ) {
    	coarse_time =       (uint32_t)  tv.tv_sec;
    	fine_time   = U2P * (uint32_t)  tv.tv_usec;
    }

    pcapnc_network_encode_uint32(buf+ 0, coarse_time);
    pcapnc_network_encode_uint32(buf+ 4, fine_time);
    pcapnc_network_encode_uint32(buf+ 8, caplen);
    pcapnc_network_encode_uint32(buf+12, orglen);
      
    ret = pcapnc_fwrite(buf, 1, PACKET_HEADER_SIZE+caplen, stdout);

	  s3sim_sleep(param_interval_sec);
  }
  
  debug_fprintf(stderr, "ret=%zd\n", ret);
  
  return 0;
}
