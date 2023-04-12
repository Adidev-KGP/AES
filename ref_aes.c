#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>


const uint8_t SBox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0 
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};


uint32_t aes128_extended_key[4*11] = {
    0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
    0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
    0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
    0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
    0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
    0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
    0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
    0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
    0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
    0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
    0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6
};



uint8_t GMul(uint8_t a, uint8_t b) {
	uint8_t p = 0;
	while (a != 0 && b != 0) {
        if (b & 1) {
            p ^= a;
        }
        if (a & 0x80) {
            a = (a << 1) ^ 0x11b;
        }
        else {
            a <<= 1; 
        }
        b >>= 1;
	}
	return p;
}

void AddRoundKey (uint32_t state[4], uint32_t extended_key[4*11], size_t round) {
    for (size_t i=0; i<4; i++) {
        state[i] ^= extended_key[4*round + i];
    }

    //  for(int j=0; j < 4; j++){
    //     printf("%s %x\n","AddRoundKey" , state[j]);
    // }
}

void MixColumns(uint32_t state[4]) {
    uint8_t s0, s1, s2, s3;
    uint8_t o0, o1, o2, o3;

    for (size_t i=0; i<4; i++) {
        s0 = state[i] & 0xFF;
        s1 = (state[i] & 0xFF00) >> 8;
        s2 = (state[i] & 0xFF0000) >> 16;
        s3 = state[i] >> 24;
        o0 = GMul(s0, 2) ^ GMul(s1, 1) ^ GMul(s2, 1) ^ GMul(s3, 3);
        o1 = GMul(s0, 3) ^ GMul(s1, 2) ^ GMul(s2, 1) ^ GMul(s3, 1);
        o2 = GMul(s0, 1) ^ GMul(s1, 3) ^ GMul(s2, 2) ^ GMul(s3, 1);
        o3 = GMul(s0, 1) ^ GMul(s1, 1) ^ GMul(s2, 3) ^ GMul(s3, 2);
        state[i] = (o3 << 24) ^ (o2 << 16) ^ (o1 << 8) ^ o0;
    }

     for(int j=0; j < 4; j++){
        printf("%s %x\n","Mix Columns", state[j]);
    }
}

void ShiftRows(uint32_t state[4]) {
    uint32_t s0 = state[0];
    uint32_t s1 = state[1];
    uint32_t s2 = state[2];
    uint32_t s3 = state[3];

    state[0] = (s0 & 0xFF000000) ^ (s1 & 0xFF0000) ^ (s2 & 0xFF00) ^ (s3 & 0xFF);
    state[1] = (s1 & 0xFF000000) ^ (s2 & 0xFF0000) ^ (s3 & 0xFF00) ^ (s0 & 0xFF);
    state[2] = (s2 & 0xFF000000) ^ (s3 & 0xFF0000) ^ (s0 & 0xFF00) ^ (s1 & 0xFF);
    state[3] = (s3 & 0xFF000000) ^ (s0 & 0xFF0000) ^ (s1 & 0xFF00) ^ (s2 & 0xFF);

    for(int j=0; j < 4; j++){
        printf("%s %x\n","Shift Rows", state[j]);
    }

}

void SubBytes(uint32_t state[4]) {
    uint8_t s0, s1, s2, s3; // shi h each byte of word extract kr rha h
    for (size_t i=0; i<4; i++) {
        s0 = state[i] & 0xFF;
        s1 = (state[i] & 0xFF00) >> 8;  // right shift use hua h 
        s2 = (state[i] & 0xFF0000) >> 16;
        s3 = state[i] >> 24;
        //state[i] = (SBox[s3] >> 24) ^ (SBox[s2] >> 16) ^ (SBox[s1] >> 8) ^ SBox[s0]; //ORIGINAL LINE//  // isme left shift use hona chahiye
        state[i] = (SBox[s3] << 24) ^ (SBox[s2] << 16) ^ (SBox[s1] << 8) ^ SBox[s0]; //correct
    }

    //  for(int j=0; j < 4; j++){
    //     printf("%s %x\n","Substitute Bytes", state[j]);
    // }
}

void aes128_encryption(uint32_t aes128_state[4], uint32_t aes128_extendedkey[4*11]) {
    // Initial AddRoundKey
    AddRoundKey(aes128_state, aes128_extended_key, 0);

    // for(int i=0; i < 4; i++){
    //     printf("%x\n", aes128_state[i]);
    // }

    //printf("\n");

    // AES Round Functions
    for (size_t i=1; i<10; i++) {
        SubBytes(aes128_state);
        ShiftRows(aes128_state);
        MixColumns(aes128_state);
        AddRoundKey(aes128_state, aes128_extended_key, i);

    //     for(int j=0; j < 4; j++){
    //     printf("%s %ld %x\n","Round", i , aes128_state[j]);
    // }

    }
    // Last Round
    SubBytes(aes128_state);
    // MixColumns(aes128_state); // ORIGINAL CODE m ha // ShiftRows call hoag idhr
    ShiftRows(aes128_state); // CORRECT h ye
    AddRoundKey(aes128_state, aes128_extendedkey, 10);
    
//    for(int j=0; j < 4; j++){
//         printf("%s %d %x\n","Round", 10 , aes128_state[j]);
//     }
}

void print_state(uint32_t aes128_state[4], char *text){

    printf("%s\n", text);

    for(int j=0; j < 4; j++){
        printf("%x\n", aes128_state[j]);
    }
    printf("\n");
}

int main (int argc, char *argv[]) {


    /* Intializes random number generator */
    time_t t;
    srand((unsigned) time(&t));

    uint32_t aes128_state[4] = {0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a}; //INITIAL yhi tha

   //uint32_t aes128_state[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
    
    // print_state(aes128_state, "initial state");    // prefered uint64_t and %ld

    // AddRoundKey(aes128_state, aes128_extended_key, 0);

    // print_state(aes128_state, "After 0th round key before entering the main rounds");

    // SubBytes(aes128_state);

    // print_state(aes128_state,"After 1st subBytes");

    // ShiftRows(aes128_state);

    // print_state(aes128_state, "After 1st shift row");

    // MixColumns(aes128_state);

    // print_state(aes128_state , "After mixing columns");

    // AddRoundKey(aes128_state, aes128_extended_key, 1);

    // print_state(aes128_state, "After 1st round key before entering the main rounds");

/*
    for(int i=0; i < 4; i++){
        printf("%ld\n", aes128_state[i]);
    }
*/
    aes128_encryption (aes128_state, aes128_extended_key);

    print_state(aes128_state, "After AES");

    // FILE *fptr;
    // fptr = fopen("/path/to/aes.diehard", "a");
    // if (fptr == NULL) {
    //     printf("Could not read file\n");
    //     exit(1);
    // }


    // aes128_state[0] = 0;
    // aes128_state[1] = 0;
    // aes128_state[2] = 0;
    // aes128_state[3] = 0;

    // for (size_t nb_sample=0; nb_sample<1000; nb_sample ++) {    

    //     aes128_encryption (aes128_state, aes128_extended_key);
    //     for (size_t i=0; i<4; i++) {
    //         fprintf(fptr, "%u", aes128_state[i]);
    //     }
    //     fprintf(fptr, "\n");
    //     aes128_state[0] += 1;
    // }

    // fclose(fptr);

    return 0;
}