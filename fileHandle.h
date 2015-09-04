#include "aes.h"

#define ENC_FILENAME "cipher.bin"
#define DEC_FILENAME "plain2.bin"

/********** fileHandle.c **********/
void fileOpenCheck(int, unsigned char**);
void fileSizeCheck();
void copyKeyFile(unsigned char*);
void plain2cipher(unsigned char*);
void cipher2plain(unsigned char*);
FILE* inputFile;
FILE* keyFile;
int textSize;
/******************************/