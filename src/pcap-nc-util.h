#include <stdio.h>
#include <stdint.h>

uint32_t pcapnc_extract_uint32(int exec_bswap, void *ptr);
uint16_t pcapnc_extract_uint16(int exec_bswap, void *ptr);
void     pcapnc_network_encode_uint32(void *ptr, uint32_t value);
uint32_t pcapnc_network_decode_uint32(void *ptr);

#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__)

#define PCAP_HEADER_SIZE    24
#define PACKET_HEADER_SIZE  16
#define PACKET_DATA_MAX_SIZE 0x10006

class pcap_file {
  public:
  uint32_t p2n;
  int exec_bswap;

  uint32_t coarse_time;
  uint32_t nanosec;
  uint32_t caplen;
  uint32_t orglen;

  private:
  size_t read(void *buf, size_t nmemb);
  public:
  size_t write(const void *buf, size_t nmemb);

  public:
  int read_nohead(FILE       *rp);
  int read_nohead(const char *filename);
  int read_head  (const char *filename);
  int read_head  (FILE       *rp);

  int write_nohead(FILE       *wp);
  int write_head  (const char *filename, uint8_t linktype);
  int write_head  (FILE       *wp,       uint8_t linktype);

  int read_packet_header(uint8_t record_buffer[], size_t buffer_size, const char *prog_name, const char *source_name);
  int read_packet_data  (uint8_t record_buffer[], const char *prog_name, const char *source_name);

  int write_packet_record(uint32_t coarse_time, uint32_t nanosec, const uint8_t outbuf[], size_t outlen, const char *prog_name, const char *source_name);

  uint16_t extract_uint16(void *ptr);
  uint32_t extract_uint32(void *ptr);

  private:
  FILE *rp;
  FILE *wp;
};
