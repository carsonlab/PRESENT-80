#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "present.h"


static void addRoundKey(uint8_t *state, uint8_t *round_key);
static void sBoxLayer(uint8_t *state);
static void inv_sBoxLayer(uint8_t *state);
static void pLayer(uint8_t *state);
static void inv_pLayer(uint8_t *state);
static void updateKey80(uint8_t *key, uint8_t *round_key, int round);


static const uint8_t sbox[16]={
  0xC,0x5,0x6,0xB,
  0x9,0x0,0xA,0xD,
  0x3,0xE,0xF,0x8,
  0x4,0x7,0x1,0x2
};

static const uint8_t inv_sbox[16]={
  0x5,0xE,0xF,0x8,
  0xC,0x1,0x2,0xD,
  0xB,0x4,0x6,0x3,
  0x0,0x7,0x9,0xA
};

static const uint8_t pbox[64]={
  0,16,32,48,1,17,33,49,
  2,18,34,50,3,19,35,51,
  4,20,36,52,5,21,37,53,
  6,22,38,54,7,23,39,55,
  8,24,40,56,9,25,41,57,
  10,26,42,58,11,27,43,59,
  12,28,44,60,13,29,45,61,
  14,30,46,62,15,31,47,63
};

static const uint8_t inv_pbox[64]={
  0,4,8,12,16,20,24,28,
  32,36,40,44,48,52,56,60,
  1,5,9,13,17,21,25,29,
  33,37,41,45,49,53,57,61,
  2,6,10,14,18,22,26,30,
  34,38,42,46,50,54,58,62,
  3,7,11,15,19,23,27,31,
  35,39,43,47,51,55,59,63
};

// Assumes key_in array is little endian (location 0 is least significant)
//void present80Encrypt(uint8_t *key_in, uint8_t *plaintext, uint8_t *ciphertext){
void present80Encrypt(uint8_t *key_in, uint8_t *text){
  int round;
  uint8_t key[10];
  uint8_t round_key[8];
  uint8_t *STATE;

  //Not super elegant, but allows the code's naming convention to match the actual algorithm
  STATE=text;

  memmove(key,key_in,10);
  memmove(round_key,&key[2],8);
	
  for(round=1;round<32;round++){
    addRoundKey(STATE, round_key);
    sBoxLayer(STATE);
    pLayer(STATE);
    updateKey80(key,round_key,round);
  }
  addRoundKey(STATE, round_key);
  // STATE points to the cipher text
}

// Uses key to decrypt the cipher text
// Result is returned in *text
// Assumes key_in array is little endian (location 0 is least significant byte)
void present80Decrypt(uint8_t *key_in, uint8_t *text){

    uint8_t key[32][10];
    uint8_t round_key[32][8];
    int round;
    uint8_t* STATE;

    //Not super elegant, but allows the code's naming convention to match the actual algorithm
    STATE = text;

    memmove(round_key[0],&key_in[2],8);
    memmove(key[0],key_in,10);

    for(round=1;round<32;round++){
        memmove(round_key[round],round_key[round-1],8);
        memmove(key[round],key[round-1],10);
        updateKey80(key[round],round_key[round],round);
    }

    for(round=31;round>0;round--){
        addRoundKey(STATE, round_key[round]);
        inv_pLayer(STATE);
        inv_sBoxLayer(STATE);
    }
    addRoundKey(STATE, round_key[0]);
    // STATE points to the decrypted text
} // end present80Decrypt()

void testPresent80(void){
    uint8_t text[8];
    uint8_t key[10];
    int i;

    // Hard code the plaintext and key to all 1's
    memset(text,0xFF,8);
    memset(key,0xFF,10);

    printf("Testing PRESENT-80\n");
    printf("Text is: 0x");
    for(i=7;i>=0;i--){printf("%02x",text[i]);}

    printf("\nKey is: 0x");
    for(i=9;i>=0;i--){printf("%02x",key[i]);}

    present80Encrypt(key,text);

    printf("\nCiphertext is: 0x");
    for(i=7;i>=0;i--){printf("%02x",text[i]);}

    present80Decrypt(key,text);

    printf("\nDecrypted text is: 0x");
    for(i=7;i>=0;i--){printf("%02x",text[i]);}

    printf("\nEnd PRESENT-80 Test\n\n");

}

static void addRoundKey(uint8_t *state, uint8_t *round_key){
  int i;
  for(i=0;i<8;i++){
    state[i]=(state[i])^(round_key[i]);
  }
}

static void sBoxLayer(uint8_t *state){
  int i;
  uint8_t dummy;
  for(i=0;i<8;i++){
    dummy=0;
    dummy |= sbox[state[i] & 0x0F];
    dummy |= (sbox[(state[i] & 0xF0) >> 4] << 4);
    state[i]=dummy;
  }
}

static void inv_sBoxLayer(uint8_t *state){
  int i;
  uint8_t dummy;
  for(i=0;i<8;i++){
    dummy=0;
    dummy |= inv_sbox[state[i] & 0x0F];
    dummy |= (inv_sbox[(state[i] & 0xF0) >> 4] << 4);
    state[i]=dummy;
  }
}

static void pLayer(uint8_t *state){
  uint8_t dummy1[64];
  uint8_t dummy2[64];
  int i;

  for(i=0;i<64;i++){
    dummy1[i]=(state[i/8]&(1<<(i%8)))>>(i%8);
  }

  for(i=0;i<64;i++){
    dummy2[pbox[i]]=dummy1[i];
  }
  
  for(i=0;i<8;i++){
    state[i] = 0; 
    state[i] |= dummy2[i*8];
    state[i] |= dummy2[(i*8)+1] << 1;
    state[i] |= dummy2[(i*8)+2] << 2;
    state[i] |= dummy2[(i*8)+3] << 3;
    state[i] |= dummy2[(i*8)+4] << 4;
    state[i] |= dummy2[(i*8)+5] << 5;
    state[i] |= dummy2[(i*8)+6] << 6;
    state[i] |= dummy2[(i*8)+7] << 7;
  }
}

static void inv_pLayer(uint8_t *state){
  uint8_t dummy1[64];
  uint8_t dummy2[64];
  int i;

  for(i=0;i<64;i++){
    dummy1[i]=(state[i/8]&(1<<(i%8)))>>(i%8);
  }

  for(i=0;i<64;i++){
    dummy2[inv_pbox[i]]=dummy1[i];
  }

  for(i=0;i<8;i++){
    state[i] = 0;
    state[i] |= dummy2[i*8];
    state[i] |= dummy2[(i*8)+1] << 1;
    state[i] |= dummy2[(i*8)+2] << 2;
    state[i] |= dummy2[(i*8)+3] << 3;
    state[i] |= dummy2[(i*8)+4] << 4;
    state[i] |= dummy2[(i*8)+5] << 5;
    state[i] |= dummy2[(i*8)+6] << 6;
    state[i] |= dummy2[(i*8)+7] << 7;
  }
}

static void updateKey80(uint8_t *key, uint8_t *round_key, int round){
  uint8_t new_key[10];
  int i;
  uint8_t box_out;
  uint8_t xor_out;

  for(i=0;i<10;i++){
    new_key[i]=0;
  }

  //Rotate by 61 bits to the left
  //Bit 0 becomes bit 19, bit 1 becomes bit 20, etc.
  for(i=0;i<10;i++){
    new_key[i] = (key[(i+3)%10] << 5) & 0xE0;     //Upper 5 bits
    new_key[i] |= ((key[(i+2)%10] >> 3) & 0x1F);  //Lower 3 bits
  }

  //Get the sbox values for bits 79 through 76
  box_out = sbox[(new_key[9]&0xF0)>>4];
  new_key[9] &= 0x0F;
  new_key[9] |= box_out << 4;

  //XOR bits 19 through 16
  xor_out = (round & 0x1E) >> 1;
  new_key[2] ^= xor_out;

  //See if bit 15 needs to be xor'd with 1
  if(round%2 == 1){new_key[1] ^= 0x80;}

  //Update the keys
  key[0]=new_key[0];
  key[1]=new_key[1];
  for(i=2;i<10;i++){
    key[i]=new_key[i];
    round_key[i-2]=key[i];
  }
}// end updateKey80()
