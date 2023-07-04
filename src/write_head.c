#include <stdio.h>
// fwrite
#include <stdlib.h>
// atoi

static char buf[] = {
  0xa1, 0xb2, 0x3c, 0x4d, // Magic Number (nanosec)
  0x00, 0x02, 0x00, 0x04, // Major Version, Minor Version
  0x00, 0x00, 0x00, 0x09, // Reserved1 (Time Zone)
  0x00, 0x00, 0x00, 0x00, // Reserved2 (Sig Fig)
  0x00, 0x01, 0x00, 0x12, // SnapLen
  0x00, 0x00, 0x00, 0xFF  // Link Type 
};

// 0x93 = 147 = DLT_USER0 - DIOSA TELEM
// 0x94 = 148 = DLT_USER1 - Space Packet
// 0x95 = 149 = DLT_USER2 - SpaceWire
   
int main(int argc, char *argv[]){

  buf[23] = atoi(argv[1]);
  fwrite(buf, 1, sizeof(buf), stdout);
  return 0;
}
