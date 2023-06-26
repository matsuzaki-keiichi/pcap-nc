#include <stdio.h>
#include <stdlib.h>
// atoi
// atof
#include <unistd.h>
// sleep
#include <stdint.h>
#include <inttypes.h>
// PRIx32
#include <time.h>
// nanosleep
#include <sys/time.h>
// gettimeofday
#include <math.h>
// floor
#include <arpa/inet.h>
// htonl
#include <byteswap.h>
// bswap_32 (gcc)
#include <getopt.h>

#define PCAP_HEADER_SIZE    24
#define PACKET_HEADER_SIZE  16
#define PACKET_DATA_MAX_SIZE 0x10006

#define MAGIC_NUMBER_USEC   0xA1B2C3D4
#define MAGIC_NUMBER_NSEC   0xA1B23C4D
#define PCAP_MAJOR_VERSION   2
#define PCAP_MINOR_VERSION   4

#define READ_RETRY 1 // sec
#define WRITE_RETRY 1 // sec

#define ERROR_1 1
#define ERROR_2 2
#define ERROR_3 3
#define ERROR_4 4
#define ERROR_5 5
#define ERROR_6 6
#define ERROR_7 7

// #define DEBUG

#ifdef DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif

static size_t force_fread(void *buf, size_t size, size_t nmemb, FILE *fp){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {
    debug_fprintf(stderr, "remaining_nmemb=%zd\n", remaining_nmemb);
	    
    ret = fread(buf, size, remaining_nmemb, fp);

    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      if ( feof(fp) ) break;
      if ( ferror(fp) ) break;
      sleep(READ_RETRY);
    }
  }
  return nmemb - remaining_nmemb;
}

static size_t force_fwrite(const void *buf, size_t size, size_t nmemb, FILE *fp){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {
    debug_fprintf(stderr, "remaining_nmemb=%zd\n", remaining_nmemb);
	    
    ret = fwrite(buf, size, remaining_nmemb, fp);

    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      if ( feof(fp) ) break;
      if ( ferror(fp) ) break;
      sleep(WRITE_RETRY);
    }
  }
  return nmemb - remaining_nmemb;
}

static double s3sim_sleep(double tdiff){

  if ( tdiff <= 0.0 ) {
    return 0.0;
  }

  const double coarse_dtime = floor(tdiff);
  const long fine_dtime = (long)((tdiff - coarse_dtime) * 1e9);
  struct timespec ts_req = {(time_t)coarse_dtime, fine_dtime};
  struct timespec ts_rem;
  
  int iret = 1;
  while (iret) {
    iret = nanosleep(&ts_req, &ts_rem);
    ts_req.tv_sec  = ts_rem.tv_sec;
    ts_req.tv_nsec = ts_rem.tv_nsec;
  }
  
  return 0.0;
}

#if 0
static double s3sim_time(){
  struct timeval tv;

  int iret = gettimeofday(&tv, NULL);

  time_t      sec  = tv.tv_sec;
  suseconds_t usec = tv.tv_usec;

  return sec + usec * 1e-6;
}
#endif

uint32_t extract_uint32(int exec_bswap, void *ptr){
  const uint32_t value = * (uint32_t*) ptr;
  return (exec_bswap) ? bswap_32(value) : value;
}

uint16_t extract_uint16(int exec_bswap, void *ptr){
  const uint16_t value = * (uint16_t*) ptr;
  return (exec_bswap) ? bswap_16(value) : value;
}

void network_encode_uint32(void *ptr, uint32_t value){
  * (uint32_t*) ptr = htonl( value );
}


#define OPTSTRING ""

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
    
  char buf[PACKET_HEADER_SIZE+PACKET_DATA_MAX_SIZE];

  ssize_t ret;

  ret = force_fread(buf, 1, PCAP_HEADER_SIZE, stdin);
  if ( ret == 0 ) {
    fprintf(stderr, "No input (missing header).\n");
    return ERROR_1;
  } else if ( ret < PCAP_HEADER_SIZE ) {
    fprintf(stderr, "File size smaller than the PCAP Header.\n");
    return ERROR_2;
  }

  const uint32_t magic_number = *(uint32_t*)&(buf[ 0]);
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

  const uint32_t major_version = extract_uint16(exec_bswap, buf+4 );
  const uint32_t minor_version = extract_uint16(exec_bswap, buf+6 );

  if ( major_version != PCAP_MAJOR_VERSION || minor_version != PCAP_MINOR_VERSION ) {
    fprintf(stderr, "File is not a PCAP file (unexpected version number=%" PRId16 ".%" PRId16 ").\n",
	    major_version, minor_version);
    return ERROR_4;
  }

  double prev_time = -1;
  
  while(1){
    ret = force_fread(buf, 1, PACKET_HEADER_SIZE, stdin);
    if ( ret < PACKET_HEADER_SIZE ) {
      fprintf(stderr, "Unexpected end of file (partial packet header).\n");
      return ERROR_5;
    }
    const uint32_t coarse_time = extract_uint32(exec_bswap, buf+ 0);
    const uint32_t fine_time   = extract_uint32(exec_bswap, buf+ 4);
    const uint32_t caplen      = extract_uint32(exec_bswap, buf+ 8);
    const uint32_t orglen      = extract_uint32(exec_bswap, buf+12);

    double curr_time = coarse_time + fine_time * finetime_unit;

    if ( caplen > PACKET_DATA_MAX_SIZE ) {
      fprintf(stderr, "Unexpected packet header (caplen(=%" PRIx32 ") too long).\n", caplen);
      return ERROR_6;
    }
    
    ret = force_fread(&(buf[PACKET_HEADER_SIZE]), 1, caplen, stdin);
    if ( ret < caplen ) {
      fprintf(stderr, "Unexpected end of file (partial packet data).\n");
      return ERROR_7;
    }

    // update Packet Header (ending conversion is performed if needed)


    if (!param_original_time) {
      struct timeval tv;
      
      const int iret = gettimeofday(&tv, NULL);

      if ( iret == 0 ) {
	const uint32_t now_coarse_time =       (uint32_t)  tv.tv_sec;
	const uint32_t now_fine_time   = u2p * (uint32_t)  tv.tv_usec;
	
	network_encode_uint32(buf+ 0, now_coarse_time);
	network_encode_uint32(buf+ 4, now_fine_time);
      }
    } else {
      network_encode_uint32(buf+ 0, coarse_time);
      network_encode_uint32(buf+ 4, fine_time);
    }
    network_encode_uint32(buf+ 8, caplen);
    network_encode_uint32(buf+12, orglen);
      
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

    ret = force_fwrite(buf, 1, PACKET_HEADER_SIZE+caplen, stdout);

    prev_time = curr_time;
  }
  
  debug_fprintf(stderr, "ret=%zd\n", ret);
  
  return 0;
}


