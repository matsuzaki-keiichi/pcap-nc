#include "shared_mem.h"
#include <cstring>
#include <iostream>
#define pcapnc_logerr(...) fprintf(stderr, __VA_ARGS__) 

#define PROGNAME "shared_mem: "

shared_mem::shared_mem(int key, size_t size) : shm_key(key), shm_size(size), shmid(-1), shm_data(nullptr) {}

shared_mem::~shared_mem() {
    if (shm_data != nullptr) {
        shmdt(shm_data);
    }
}

int shared_mem::write_flag_mem(const uint8_t* outbuf, size_t outlen, const uint8_t *rcvbuf, ValidateOutputs& outputs) {
    shm_data = attach();
    if (!shm_data) return -1;

    int source_path_address_length = rcvbuf[2] & 0x03; 
    int n = source_path_address_length << 2;
    uint32_t address = (((uint32_t) rcvbuf[ 8+n]) << 24)
        +              (((uint32_t) rcvbuf[ 9+n]) << 16)
        +              (((uint32_t) rcvbuf[10+n]) <<  8) 
        +              (((uint32_t) rcvbuf[11+n]) <<  0);
    uint32_t tmplen  = (((uint32_t) rcvbuf[12+n]) << 16)
        +              (((uint32_t) rcvbuf[13+n]) <<  8) 
        +              (((uint32_t) rcvbuf[14+n]) <<  0);
    
    if (outlen != tmplen) return -1;

    address = toBigEndian(address);
    tmplen =  toBigEndian(tmplen);

    memcpy(shm_data + WRITE_TARGET_ADDRESS, &address,   sizeof(address));
    memcpy(shm_data + WRITE_LENGTH,         &tmplen,    sizeof(tmplen));
    *(shm_data      + WRITE_CRC) = (uint8_t)1;
    *(shm_data      + DATA_UPDATE_FLAG) = (uint8_t)1;
 
    detach();
    return 0;
}

int shared_mem::write_rmap_mem(const uint8_t* outbuf, size_t outlen, const uint8_t *rcvbuf, ValidateOutputs& outputs) {
    shm_data = attach();
    if (!shm_data) return -1;

    int source_path_address_length = rcvbuf[2] & 0x03; 
    int n = source_path_address_length << 2;
    uint32_t address = (((uint32_t) rcvbuf[ 8+n]) << 24)
        +              (((uint32_t) rcvbuf[ 9+n]) << 16)
        +              (((uint32_t) rcvbuf[10+n]) <<  8) 
        +              (((uint32_t) rcvbuf[11+n]) <<  0);
    
    if (address < outputs.address_mem || (address + outlen) > (outputs.address_mem + outputs.length_mem)) {
        pcapnc_logerr(PROGNAME "Error: Address range out of bounds. setting Address: 0x%X, Length: %zu\n", outputs.address_mem, outputs.length_mem);
        detach();
        return -1;
    }

    memcpy(shm_data, outbuf, outlen);

    detach();  
    return 0;
}

void shared_mem::validate_read_command(const uint8_t *rcvbuf, uint32_t &address, size_t &inplen) {  
    int source_path_address_length = rcvbuf[2] & 0x03; 
    int n = source_path_address_length << 2;
    address = (((uint32_t) rcvbuf[ 8+n]) << 24)
        +     (((uint32_t) rcvbuf[ 9+n]) << 16)
        +     (((uint32_t) rcvbuf[10+n]) <<  8) 
        +     (((uint32_t) rcvbuf[11+n]) <<  0);

    inplen = (((size_t) rcvbuf[12+n]) << 16)
        +    (((size_t) rcvbuf[13+n]) <<  8) 
        +    (((size_t) rcvbuf[14+n]) <<  0);
 
    return ;
}

int shared_mem::read_rmap_mem(uint8_t* buffer, size_t buffer_len, uint32_t target_add, ValidateOutputs& outputs) {
    shm_data = attach();
    if (!shm_data) return -1;

    // アドレス範囲のチェック
    if (target_add < outputs.address_mem || (target_add + buffer_len) > (outputs.address_mem + outputs.length_mem)) {
        pcapnc_logerr(PROGNAME "Error: Address range out of bounds. Target Address: 0x%X, Length: %zu\n", target_add, buffer_len);
        detach();
        return -1;
    }
    target_add = target_add - outputs.address_mem;

    memcpy(buffer, shm_data + target_add, buffer_len);
    detach();  
    return 0;
}

uint8_t* shared_mem::attach() {
    shmid = shmget(shm_key, shm_size, 0666| IPC_CREAT);
    if (shmid == -1) {
        pcapnc_logerr(PROGNAME "Failed to obtain shared memory segment\n");
        return nullptr;
    }

    shm_data = (uint8_t*)shmat(shmid, NULL, 0);
    if (shm_data == (void*)-1) {
        pcapnc_logerr(PROGNAME "Failed to attach to shared memory\n");
        shm_data = nullptr;
    }
    return shm_data;
}

void shared_mem::detach() {
    if (shm_data) {
        shmdt(shm_data);
        shm_data = nullptr;
    }
}


uint32_t shared_mem::toBigEndian(uint32_t value) {
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0xFF000000) >> 24);
}


int shared_mem::validate_option(const char* param_shared_mem, shared_mem::ValidateOutputs& outputs) {
    char buffer[1024];
    strncpy(buffer, param_shared_mem, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null-termination

    char* token;
    char* rest = buffer;
    bool key_found = false, remote_buffer_address_found = false, device_register_address_found = false;

    while ((token = strtok_r(rest, ",", &rest))) {
        char* key;
        char* sub_rest = token;

        key = strtok_r(sub_rest, ":", &sub_rest);
        if (key == NULL || sub_rest == NULL || *sub_rest == '\0') {
            pcapnc_logerr(PROGNAME "option '--shared-memory' is invalid_argument. Key or value missing or empty in token '%s'.\n", token);  // @ test-shm1-1.sh
            return -1;
        }

        if (strcmp(key, "key") == 0) {
            key_found = true;
            snprintf(outputs.key_mem, sizeof(outputs.key_mem), "%s-mem", sub_rest);
            snprintf(outputs.key_reg, sizeof(outputs.key_reg), "%s-reg", sub_rest);
        } else if (strcmp(key, "RemoteBufferAddress") == 0) {
            remote_buffer_address_found = true;
            char* address = strtok_r(sub_rest, "#", &sub_rest);
            char* size_key = strtok_r(sub_rest, ":", &sub_rest);
            char* size_value = sub_rest;

            if (!address || !size_key || strcmp(size_key, "RemoteBufferSize") != 0 || !size_value) {
                pcapnc_logerr(PROGNAME "option '--shared-memory' is invalid_argument. Address or size missing in token '%s'.\n", token);  // @ test-shm1-2.sh
                return -1;
            }

            char* endptr;
            uint32_t addr = (uint32_t) strtol(address, &endptr, 16);
            if (*endptr != '\0') {
                pcapnc_logerr(PROGNAME "option '--shared-memory' is invalid_argument. Invalid address format '%s'.\n", address);    // @ test-shm1-3.sh
                return -1;
            }

            size_t len = (size_t) strtol(size_value, &endptr, 10);
            if (*endptr != '\0') {
                pcapnc_logerr(PROGNAME "option '--shared-memory' is invalid_argument. Invalid size format '%s'.\n", size_value);    // @ test-shm1-4.sh
                return -1;
            }

            outputs.address_mem = addr;
            outputs.length_mem = len;
        } else if (strcmp(key, "DeviceRegisterAddress") == 0) {
            device_register_address_found = true;
            char* address = sub_rest;

            char* endptr;
            uint32_t addr = (uint32_t) strtol(address, &endptr, 16);
            if (*endptr != '\0') {
                pcapnc_logerr(PROGNAME "option '--shared-memory' is invalid_argument. Invalid address format '%s'.\n", address);    // @ test-shm1-5.sh
                return -1;
            }

            outputs.address_reg = addr;
            outputs.length_reg = DEV_REG_SIZE;  // ヘッダファイルで指定（固定値）
        } else {
            pcapnc_logerr(PROGNAME "option '--shared-memory' is invalid_argument. Invalid key '%s'.\n", key);   // @ test-shm1-6.sh
            return -1;
        }
    }

    if (!key_found || !remote_buffer_address_found || !device_register_address_found) {
        pcapnc_logerr(PROGNAME "option '--shared-memory' is invalid_argument. All required keys ('key', 'RemoteBufferAddress', 'DeviceRegisterAddress') must be provided.\n");
        return -1; 
    }

    return 0; // No errors found
}
