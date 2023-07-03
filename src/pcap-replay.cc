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

#include "rmap_channel.h"
#include "pcap-nc-util.h"
#include "s3sim.h"

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

#define RMAPW 1

static int verbose_flag = 0;

static struct option long_options[] = {
  {"after",         required_argument, NULL, 'a'},
  {"interval",      required_argument, NULL, 'i'},
  {"original-time",       no_argument, NULL, 'o'},
  { NULL,      0,                 NULL,  0 }
};

static double param_wait_time     = 0.0;
static double param_interval_sec  = 0.0;
static int    param_original_time = 0;

int main(int argc, char *argv[])
{
  //// parse options
  
  int option_error = 0;
  
  while (1) {

    int option_index = 0;
    const int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

    if ( c == -1 ) break;
    
    switch (c) {
    case 'a': param_wait_time    = atof(optarg); if (param_wait_time    < 0.0) param_wait_time    = 0.0; break;
    case 'i': param_interval_sec = atof(optarg); if (param_interval_sec < 0.0) param_interval_sec = 0.0; break;
    case 'o': param_original_time = 1; break;
    default: option_error=1; break;
    }
  }
  if (option_error) {
    return 1;
  }
  
  debug_fprintf(stderr, "param_wait_time=%u\n", param_wait_time);

  ////
    
  static uint8_t inbuf  [PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];
  static uint8_t outbuf [PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  ssize_t ret;

  ret = pcapnc_fread(inbuf, 1, PCAP_HEADER_SIZE, stdin);
  if ( ret == 0 ) {
    fprintf(stderr, "No input (missing header).\n");
    return ERROR_1;
  } else if ( ret < PCAP_HEADER_SIZE ) {
    fprintf(stderr, "File size smaller than the PCAP Header.\n");
    return ERROR_2;
  }

  const uint32_t magic_number = *(uint32_t*)&(inbuf[ 0]);
  const uint32_t magic_number_swap = bswap_32(magic_number);
  double finetime_unit;
  uint32_t u2p;
  int exec_bswap;
  
  if      ( magic_number      == MAGIC_NUMBER_USEC ) { finetime_unit = 1e-6; u2p = 1;    exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_USEC ) { finetime_unit = 1e-6; u2p = 1;    exec_bswap = 1; }
  else if ( magic_number      == MAGIC_NUMBER_NSEC ) { finetime_unit = 1e-9; u2p = 1000; exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_NSEC ) { finetime_unit = 1e-9; u2p = 1000; exec_bswap = 1; }
  else {
    fprintf(stderr, "File is not a PCAP file (bad magic number).\n");
    return ERROR_3;
  }

  const uint32_t major_version = extract_uint16(exec_bswap, inbuf+4 );
  const uint32_t minor_version = extract_uint16(exec_bswap, inbuf+6 );

  if ( major_version != PCAP_MAJOR_VERSION || minor_version != PCAP_MINOR_VERSION ) {
    fprintf(stderr, "File is not a PCAP file (unexpected version number=%" PRId16 ".%" PRId16 ").\n",
	    major_version, minor_version);
    return ERROR_4;
  }

  double prev_time = -1;
  
#if RMAPW
  class rmap_write_channel rmapw;

  rmapw.read_json("sample.json", "channel1");
#endif

  while(1){
    ret = pcapnc_fread(inbuf, 1, PACKET_HEADER_SIZE, stdin);
    if ( ret < PACKET_HEADER_SIZE ) {
      fprintf(stderr, "Unexpected end of file (partial packet header).\n");
      return ERROR_5;
    }
    const uint32_t coarse_time = extract_uint32(exec_bswap, inbuf+ 0);
    const uint32_t fine_time   = extract_uint32(exec_bswap, inbuf+ 4);
    const uint32_t caplen      = extract_uint32(exec_bswap, inbuf+ 8);
    const uint32_t orglen      = extract_uint32(exec_bswap, inbuf+12);

    double curr_time = coarse_time + fine_time * finetime_unit;

    if ( caplen > PACKET_DATA_MAX_SIZE ) {
      fprintf(stderr, "Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", caplen);
      return ERROR_6;
    }
    
    ret = pcapnc_fread(&(inbuf[PACKET_HEADER_SIZE]), 1, caplen, stdin);
    if ( ret < caplen ) {
      fprintf(stderr, "Unexpected end of file (partial packet data).\n");
      return ERROR_7;
    }

    // generated output (ending conversion is performed if needed)

    if (!param_original_time) {
      struct timeval tv;
      
      const int iret = gettimeofday(&tv, NULL);

      if ( iret == 0 ) {
      	const uint32_t now_coarse_time =       (uint32_t)  tv.tv_sec;
      	const uint32_t now_fine_time   = u2p * (uint32_t)  tv.tv_usec;
	
      	network_encode_uint32(outbuf+ 0, now_coarse_time);
      	network_encode_uint32(outbuf+ 4, now_fine_time);
      }
    } else {
      network_encode_uint32(outbuf+ 0, coarse_time);
      network_encode_uint32(outbuf+ 4, fine_time);
    }

#if RMAPW
    const size_t insize  = caplen;
    size_t outsize = PACKET_DATA_MAX_SIZE;

    rmapw.send_witouht_ack(inbuf+16, insize, outbuf+16, &outsize);

    const size_t outlen = outsize;
#else    
    memcpy(outbuf+16, inbuf+16, caplen);

    const size_t outlen = caplen;
#endif

    network_encode_uint32(outbuf+ 8, outlen);
    network_encode_uint32(outbuf+12, outlen);

    if ( prev_time < 0 ) {

      s3sim_sleep(param_wait_time);

    } else {
      const double tdiff = curr_time - prev_time;

      if ( param_interval_sec == 0.0 ) {
	      s3sim_sleep(tdiff);
      } else {
      	s3sim_sleep(param_interval_sec);
      }
    }
    debug_fprintf(stderr, "curr_time=%f\n", curr_time);

    ret = pcapnc_fwrite(outbuf, 1, PACKET_HEADER_SIZE+outlen, stdout);

    prev_time = curr_time;
  }
  
  debug_fprintf(stderr, "ret=%zd\n", ret);
  
  return 0;
}
