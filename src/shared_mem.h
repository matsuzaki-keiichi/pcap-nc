#ifndef SHARED_MEM_H
#define SHARED_MEM_H

#include <cstdint>
#include <cstdio>
#include <sys/ipc.h>
#include <sys/shm.h>

// shared mem settings       
#define DEV_REG_SIZE 16          

// flag mem
#define DATA_UPDATE_FLAG        0x00000000
#define TIMECODE                0x00000001
#define WRITE_TARGET_ADDRESS    0x00000005
#define WRITE_LENGTH            0x00000009
#define WRITE_CRC               0x0000000D


class shared_mem {
public:
    struct ValidateOutputs {
        char key_mem[1024];
        char key_reg[1024];
        uint32_t address_mem;
        uint32_t address_reg;
        size_t length_mem;
        size_t length_reg;
    };
    
    shared_mem(int key, size_t size);
    ~shared_mem();

    static int validate_option(const char* param_shared_mem, ValidateOutputs& outputs);
    void validate_read_command(const uint8_t *rcvbuf, uint32_t &address, size_t &inplen);
    int read_rmap_mem(uint8_t* buffer, size_t buffer_len, uint32_t target_add, ValidateOutputs& outputs);  
    int write_flag_mem(const uint8_t* outbuf, size_t outlen, const uint8_t *rcvbuf, ValidateOutputs& outputs);
    int write_rmap_mem(const uint8_t* outbuf, size_t outlen, const uint8_t *rcvbuf, ValidateOutputs& outputs);

private:
    int shm_key;
    size_t shm_size;
    int shmid;
    uint8_t* shm_data;
    uint8_t* attach();
    void detach();
    uint32_t toBigEndian(uint32_t value);
};

#endif // SHARED_MEM_H
