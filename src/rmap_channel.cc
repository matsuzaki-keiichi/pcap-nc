#include "rmap_channel.h"

#include <fstream>
#include <iostream>
#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"
// using namespace rapidjson;

#include <boost/algorithm/string.hpp>
#include <string>
#include <list>
#include <boost/foreach.hpp>
using namespace std;

#include <stdio.h>
#include <string.h>
// memcpy

static long long parse_hex_longlong(const char *s, const char *varname){
    if ( s[0] != '0' || s[1] != 'x' ) {
        fprintf(stderr, "%s shall start with '0x'.\n", varname);
        exit(1);        
    }

    char *endptr;
    const long long llvalue = strtoull(s+2, &endptr, 16);
    if ( *endptr != 0 ) {
        fprintf(stderr, "%s(%s) shall be a number.\n", varname, s);
        exit(1);        
    }
    return llvalue;
}

static uint8_t read_hex_uint8(const rapidjson::Value &obj, const char *varname){
    const char* s = obj[varname].GetString();
    const long long llvalue = parse_hex_longlong(s, varname);
    if ( llvalue >= 0x100 || llvalue < 0 ) {
        fprintf(stderr, "%s(%s) shall be 1 byte value.\n", varname, s);
        exit(1);        
    }
    return (uint8_t) llvalue;    
}

static uint64_t read_hex_uint40(const rapidjson::Value &obj, const char *varname){
    const char* s = obj[varname].GetString();
    const long long llvalue = parse_hex_longlong(s, varname);
    if ( llvalue >= 0x10000000000 || llvalue < 0 ) {
        fprintf(stderr, "%s shall be 5 byte value.\n", varname);
        exit(1);        
    }
    return (uint64_t) llvalue;    
}

static int read_hex_chars(const rapidjson::Value &obj, const char *varname, uint8_t out_buffer[], int buffer_size){
    const char* t = obj[varname].GetString();
    string str(t);

    list<string> list_string;
 
    boost::split(list_string, str, boost::is_space());

    int i=0;
    BOOST_FOREACH(string s, list_string) {
        if ( i>=buffer_size ) {
            fprintf(stderr, "Size of %s exceeds %d.\n", varname, buffer_size);
            exit(1);        
        }
        const long long llvalue = parse_hex_longlong(s.c_str(), varname);
        if ( llvalue >= 32 || llvalue < 0 ) {
            fprintf(stderr, "%s(%s) shall be in the range from 0 to 31.\n", varname, s.c_str());
            exit(1);        
        }
        out_buffer[i] = (uint8_t) llvalue;
        i++;
    }
    return i;
}

rmap_write_channel::rmap_write_channel(){

    num_dpa_padding = 0;   
    num_dpa         = 4;
    d_path_address[0] = 0x04;
    d_path_address[1] = 0x03;
    d_path_address[2] = 0x02;
    d_path_address[3] = 0x01;
    destination_logical_address = 0x90;
    destination_key             = 0x6f;

    num_spa_padding = 0;   
    num_spa         = 4;
    s_path_address[0] = 0x01; 
    s_path_address[1] = 0x02; 
    s_path_address[2] = 0x03; 
    s_path_address[3] = 0x04; 
    source_logical_address      = 0x91;

    write_address               = 0x6789abcdef;

    transaction_id              = 0x9999;
}

void rmap_write_channel::read_json(const char *file_name, const char *channel_name)
{
    std::ifstream ifs(file_name);
    rapidjson::IStreamWrapper isw(ifs);

    rapidjson::Document doc;
    doc.ParseStream(isw);
 
    rapidjson::Value::MemberIterator attributeIterator = doc.FindMember( "channels" );
    const rapidjson::Value& channels = doc[ "channels" ];

    for (rapidjson::Value::ConstValueIterator itr = channels.Begin(); itr != channels.End(); ++itr) {
        const rapidjson::Value& channel = *itr;

        string name = channel["name"].GetString();
        if ( name != channel_name ) continue;

        this->num_dpa = read_hex_chars(channel, "destination_path_address", this->d_path_address, RMAP_MAX_NUM_PATH_ADDRESS);
        this->num_spa = read_hex_chars(channel, "source_path_address",      this->s_path_address, RMAP_MAX_NUM_PATH_ADDRESS);

//      this->num_dpa_padding = (RMAP_MAX_NUM_PATH_ADDRESS - this->num_dpa) % 4;
        this->num_dpa_padding = 0;
        this->num_spa_padding = (RMAP_MAX_NUM_PATH_ADDRESS - this->num_spa) % 4;

        this->destination_logical_address = read_hex_uint8 (channel, "destination_logical_address");
        this->destination_key             = read_hex_uint8 (channel, "destination_key");
        this->source_logical_address      = read_hex_uint8 (channel, "source_logical_address");
        this->write_address               = read_hex_uint40(channel, "write_address");

#ifdef DEBUG
        std::cout << "destination_path_address:    " << channel["destination_path_address"]    .GetString() << std::endl;
        std::cout << "destination_logical_address: " << channel["destination_logical_address"] .GetString() << std::endl;
        std::cout << "destination_key:             " << channel["destination_key"]             .GetString() << std::endl;
        std::cout << "source_path_address:         " << channel["source_path_address"]         .GetString() << std::endl;
        std::cout << "source_logical_address:      " << channel["source_logical_address"]      .GetString() << std::endl;
        std::cout << "write_address:               " << channel["write_address"]               .GetString() << std::endl;
#endif    
    }
}

#define RMAP_PROTOCOL_ID 0x01

// Wrire Command without verify without acknowledge (0x60)
// Instruction field = RMAP Command + Source Path Address Length
//  0b: reserved
//  1b: command
//  1b: write
//  0b: no verify
//  0b: without acknowledge
//  0b: no increment
// xxb: source path address length

#define INSTRUCTION 0x60

static uint16_t transaction_id = 0x9999;

void rmap_write_channel::send_witouht_ack(const uint8_t inbuf[], size_t insize, uint8_t outbuf[], size_t *outsize){
    const int m = this->num_dpa_padding + this->num_dpa;
    const int n = this->num_spa_padding + this->num_spa;

    for ( size_t i=0 ; i<this->num_dpa_padding ; i++ ) outbuf[i] = 0x00;
    for ( size_t i=0 ; i<this->num_dpa ; i++ ) outbuf[this->num_dpa_padding+i] = this->d_path_address[i];

    uint8_t *const cargo = outbuf + m;

    cargo[ 0] = this->destination_logical_address;
    cargo[ 1] = RMAP_PROTOCOL_ID;
    cargo[ 2] = INSTRUCTION; // instruction
    cargo[ 3] = this->destination_key;

    // source path address
    for ( size_t i=0 ; i<this->num_spa_padding ; i++ ) cargo[4+i] = 0x00;
    for ( size_t i=0 ; i<this->num_spa ; i++ ) cargo[4+this->num_spa_padding+i] = this->s_path_address[i];
    cargo[ 2] = (cargo[ 2] & 0xFC) | ((n/4) & 0x03); // source path address length

    cargo[ 4+n] = this->source_logical_address;
    cargo[ 5+n] = (transaction_id      >>  8) & 0xFF;
    cargo[ 6+n] = (transaction_id      >>  0) & 0xFF;
    cargo[ 7+n] = (this->write_address >> 32) & 0xFF;
    cargo[ 8+n] = (this->write_address >> 24) & 0xFF;
    cargo[ 9+n] = (this->write_address >> 16) & 0xFF;
    cargo[10+n] = (this->write_address >>  8) & 0xFF;
    cargo[11+n] = (this->write_address >>  0) & 0xFF;
    cargo[12+n] = (insize              >> 16) & 0xFF;
    cargo[13+n] = (insize              >>  8) & 0xFF;
    cargo[14+n] = (insize              >>  0) & 0xFF;
    cargo[15+n] = rmap_calculate_crc(cargo, 15+n);

    size_t outsize0 = 16+m+n+insize+1;

    if ( outsize0 > *outsize ) {
        fprintf(stderr, "output size (%zu) exceeds the buffer size (%zu).\n", outsize0, *outsize);
        exit(1);        
    }

    uint8_t *data = cargo+16+n;
    memcpy(data, inbuf, insize); // TODO boundary chcek
    data[insize] = rmap_calculate_crc(data, insize);

    *outsize = outsize0;
    
    transaction_id = transaction_id + 1;
}

extern "C" {

// #define DEBUG

// Reference: https://gist.github.com/yuasatakayuki/e2acc1b1a40307257c14dcd4040ec1c4

static const uint8_t RMAP_CRC_TABLE[] = {
    0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75,  // 0
    0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,  // 1
    0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69,  // 2
    0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,  // 3
    0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d,  // 4
    0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,  // 5
    0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51,  // 6
    0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,  // 7
    0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05,  // 8
    0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,  // 9
    0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19,  // 10
    0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,  // 11
    0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d,  // 12
    0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,  // 13
    0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21,  // 14
    0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,  // 15

    0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95,  // 16
    0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,  // 17
    0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89,  // 18
    0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,  // 19
    0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad,  // 20
    0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,  // 21
    0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1,  // 22
    0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,  // 23
    0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5,  // 24
    0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,  // 25
    0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9,  // 26
    0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,  // 27
    0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd,  // 28
    0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,  // 29
    0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1,  // 30
    0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf   // 31
};

uint8_t rmap_calculate_crc(const uint8_t data[], size_t length) {
  uint8_t crc = 0x00;
  for (size_t i = 0; i < length; i++) {
    crc = RMAP_CRC_TABLE[(crc ^ data[i]) & 0xff];
  }
  return crc;
}

}
