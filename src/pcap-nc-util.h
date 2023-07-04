#include <stdio.h>
#include <stdint.h>

size_t pcapnc_fread(void *buf, size_t size, size_t nmemb, FILE *fp);
size_t pcapnc_fwrite(const void *buf, size_t size, size_t nmemb, FILE *fp);

uint32_t pcapnc_extract_uint32(int exec_bswap, void *ptr);
uint16_t pcapnc_extract_uint16(int exec_bswap, void *ptr);
void     pcapnc_network_encode_uint32(void *ptr, uint32_t value);
uint32_t pcapnc_network_decode_uint32(void *ptr);

#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__)

#define PCAP_HEADER_SIZE    24

class pcap_file {
  public:
  double finetime_unit;
  uint32_t u2p;
  int exec_bswap;

  int read_head(FILE *input);
  uint16_t extract_uint16(void *ptr);
  uint32_t extract_uint32(void *ptr);
};
