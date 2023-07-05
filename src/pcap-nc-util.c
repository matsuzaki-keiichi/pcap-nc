#include "pcap-nc-util.h"

#include <inttypes.h>
// PRIxN
#include <unistd.h>
// sleep
#include <arpa/inet.h>
// htonl
// ntohl
#include <byteswap.h>
// bswap_32 (gcc)
#include <stdio.h>
// setvbuf

// #define DEBUG

#define READ_RETRY  1 // sec
#define WRITE_RETRY 1 // sec

void pcapnc_unset_stdbuf(){
  int ret;
  ret = setvbuf(stdin,  NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset stdin buffer.\n");

  ret = setvbuf(stdout, NULL, _IONBF, 0);
  if ( ret != 0 ) pcapnc_logerr("Failed to Unset stdout buffer.\n");
}

size_t pcapnc_fread(void *buf, size_t size, size_t nmemb, FILE *fp){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {	    
    ret = fread(buf, size, remaining_nmemb, fp);

    if ( ret > 0 ) {
      remaining_nmemb -= ret;
    } else {
      //fprintf(stderr, "remaining_nmemb=%zu\n", remaining_nmemb);
      if ( feof(fp) ) break;
      if ( ferror(fp) ) break;
      //fprintf(stderr, "sleep 1\n");
      sleep(READ_RETRY);
    }
  }
  return nmemb - remaining_nmemb;
}

size_t pcapnc_fwrite(const void *buf, size_t size, size_t nmemb, FILE *fp){
  size_t remaining_nmemb = nmemb;
  ssize_t ret;

  while ( remaining_nmemb > 0 ) {
    // debug_fprintf(stderr, "remaining_nmemb=%zu\n", remaining_nmemb);
	    
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

uint32_t pcapnc_extract_uint32(int exec_bswap, void *ptr){
  const uint32_t value = * (uint32_t*) ptr;
  return (exec_bswap) ? bswap_32(value) : value;
}

uint16_t pcapnc_extract_uint16(int exec_bswap, void *ptr){
  const uint16_t value = * (uint16_t*) ptr;
  return (exec_bswap) ? bswap_16(value) : value;
}

void pcapnc_network_encode_uint32(void *ptr, uint32_t value){
  * (uint32_t*) ptr = htonl( value );
}

uint32_t pcapnc_network_decode_uint32(void *ptr){
  return ntohl( * (uint32_t*) ptr );
}

#define MAGIC_NUMBER_USEC   0xA1B2C3D4
#define MAGIC_NUMBER_NSEC   0xA1B23C4D
#define PCAP_MAJOR_VERSION   2
#define PCAP_MINOR_VERSION   4

#define ERROR_1 1
#define ERROR_2 2
#define ERROR_3 3
#define ERROR_4 4

int pcap_file::read_head(FILE *input){
  uint8_t inbuf[PCAP_HEADER_SIZE];

  ssize_t ret = pcapnc_fread(inbuf, 1, PCAP_HEADER_SIZE, input);
  if ( ret == 0 ) {
    pcapnc_logerr("No input (missing header).\n");
    return ERROR_1;
  } else if ( ret < PCAP_HEADER_SIZE ) {
    pcapnc_logerr("File size smaller than the PCAP Header.\n");
    return ERROR_2;
  }

  const uint32_t magic_number = *(uint32_t*)&(inbuf[ 0]);
  const uint32_t magic_number_swap = bswap_32(magic_number);
  
  if      ( magic_number      == MAGIC_NUMBER_USEC ) { this->finetime_unit = 1e-6; this->u2p = 1;    this->exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_USEC ) { this->finetime_unit = 1e-6; this->u2p = 1;    this->exec_bswap = 1; }
  else if ( magic_number      == MAGIC_NUMBER_NSEC ) { this->finetime_unit = 1e-9; this->u2p = 1000; this->exec_bswap = 0; }
  else if ( magic_number_swap == MAGIC_NUMBER_NSEC ) { this->finetime_unit = 1e-9; this->u2p = 1000; this->exec_bswap = 1; }
  else {
    pcapnc_logerr("File is not a PCAP file (bad magic number).\n");
    return ERROR_3;
  }
  this->p2n = 1000 / this->u2p;

  const uint32_t major_version = pcapnc_extract_uint16(exec_bswap, inbuf+4 );
  const uint32_t minor_version = pcapnc_extract_uint16(exec_bswap, inbuf+6 );

  if ( major_version != PCAP_MAJOR_VERSION || minor_version != PCAP_MINOR_VERSION ) {
    pcapnc_logerr("File is not a PCAP file (unexpected version number=%" PRId16 ".%" PRId16 ").\n",
	    major_version, minor_version);
    return ERROR_4;
  }
  return 0;
}

uint16_t pcap_file::extract_uint16(void *ptr){
  const uint16_t value = * (uint16_t*) ptr;
  return (this->exec_bswap) ? bswap_16(value) : value;
}

uint32_t pcap_file::extract_uint32(void *ptr){
  const uint32_t value = * (uint32_t*) ptr;
  return (this->exec_bswap) ? bswap_32(value) : value;
}

