#include "pcap-nc-util.h"

#include <unistd.h>
// sleep
#include <arpa/inet.h>
// htonl
#include <byteswap.h>
// bswap_32 (gcc)

// #define DEBUG

#define READ_RETRY  1 // sec
#define WRITE_RETRY 1 // sec

size_t pcapnc_fread(void *buf, size_t size, size_t nmemb, FILE *fp){
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

size_t pcapnc_fwrite(const void *buf, size_t size, size_t nmemb, FILE *fp){
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
