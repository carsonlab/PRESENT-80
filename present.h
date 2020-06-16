#ifndef __PRESENT_H__
#define __PRESENT_H__
#include "stdint.h"

void present80Encrypt(uint8_t *key_in, uint8_t *text);
void present80Decrypt(uint8_t *key_in, uint8_t *text);
void testPresent80(void);

#endif //__PRESENT_H__
