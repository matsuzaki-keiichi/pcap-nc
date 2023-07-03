#include <stdio.h>
#include <stdint.h>

size_t pcapnc_fread(void *buf, size_t size, size_t nmemb, FILE *fp);
size_t pcapnc_fwrite(const void *buf, size_t size, size_t nmemb, FILE *fp);

uint32_t extract_uint32(int exec_bswap, void *ptr);
uint16_t extract_uint16(int exec_bswap, void *ptr);
void network_encode_uint32(void *ptr, uint32_t value);

#ifdef DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif
