#pragma once

#ifndef _AES_H
#define _AES_H

#include <stdio.h>
#include <stdlib.h>

#define AES_BUFFER 16
#define KEY_LENGTH 16
#define NUM_ROUND 10
#define ELEMENT_S_BOX 256
#define ELEMENT_MIX_COLUMNS_MATRIX 4
#define BYTESIZ 8
#define MOD_POLYNOMIAL 0x1E7
#define S_MATRIX 0xF1
#define S_ADD_BYTE 0x63


/********** aes.c **********/
unsigned char* encrypt_AES(unsigned char*, unsigned char*);
unsigned char* decrypt_AES(unsigned char*, unsigned char*);
void make_S_BOX();
void make_RCON();
void memoExpendedKeys();
void make_LOOKUP_TABLE();
void make_INVERSE_LOOKUP_TABLE();
unsigned char* keyExpension(int);
unsigned char* R_function(int, unsigned char*);
unsigned char* referLookupTable(unsigned char*);
unsigned char* substituteByte_shiftRows(unsigned char*);
unsigned char calc_inverseByte(unsigned char);
unsigned char calc_S_MATRIX(unsigned char);
unsigned char* addRoundKey(unsigned char*, unsigned char*);
unsigned char* inverse_referLookupTable(unsigned char*);
unsigned char* inverse_substituteByte_shiftRows(unsigned char*);
void free_LOOKUP_TABLE();
void free_INVERSE_LOOKUP_TABLE();

unsigned char roundKey[NUM_ROUND][KEY_LENGTH];
unsigned char S_BOX[ELEMENT_S_BOX];
unsigned char INVERSE_S_BOX[ELEMENT_S_BOX];
unsigned char MIX_COLUMNS_MATRIX[ELEMENT_MIX_COLUMNS_MATRIX][ELEMENT_MIX_COLUMNS_MATRIX];
unsigned char INVERSE_MIX_COLUMNS_MATRIX[ELEMENT_MIX_COLUMNS_MATRIX][ELEMENT_MIX_COLUMNS_MATRIX];
unsigned char* RCON;
unsigned char*** LOOKUP_TABLE;
unsigned char*** INVERSE_LOOKUP_TABLE;
/******************************/


#endif