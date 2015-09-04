#include "aes.h"
#include "fileHandle.h"


/********** 파일 오픈 체크 **********/
void fileOpenCheck(int _argc, unsigned char** _argv)
{
	if (_argc != 3){
		printf_s("Invalid open. The valid open command is \"aes.exe (plain/cipher)Filepath keyFilepath\"\n");
		exit(1);
	}
	else if (fopen_s(&inputFile, _argv[1], "r")){
		printf_s("(plain/cipher)File open error. Please check the file \'%s\' exists.\n", _argv[1]);
		exit(1);
	}
	else if (fopen_s(&keyFile, _argv[2], "r")){
		printf_s("keyFile open error. Please check the file \'%s\' exists.\n", _argv[2]);
		exit(1);
	}
}
/******************************/


/********** 파일 사이즈 체크 **********/
void fileSizeCheck()
{
	int tempInt = ftell(inputFile);	// 텍스트 파일 체크
	fseek(inputFile, 0, SEEK_END);
	if ((textSize = ftell(inputFile) - tempInt) & (AES_BUFFER - 1)){	//파일 크기가 128비트의 배수가 아닌 경우
		printf_s("(plain/cipher)File size error. It must be a multiple of %d bits.\n", AES_BUFFER << 3);
		exit(1);
	}
	fseek(inputFile, 0, SEEK_SET);

	tempInt = ftell(keyFile);	// 키 파일 체크
	fseek(keyFile, 0, SEEK_END);
	if (ftell(keyFile) - tempInt != KEY_LENGTH){	//파일 크기가 128비트가 아닌 경우
		printf_s("keyFile size error. It must be %d bits.\n", KEY_LENGTH << 3);
		exit(1);
	}
	fseek(keyFile, 0, SEEK_SET);
}
/******************************/


/********** 키 파일 복사 **********/
void copyKeyFile(unsigned char* _buf)
{
	int i = 0;

	for (; i < KEY_LENGTH; ++i)
		_buf[i] = fgetc(keyFile);

	fclose(keyFile);
}
/******************************/


/********** 암호화 (ECB MODE) **********/
void plain2cipher(unsigned char* _key)
{
	FILE* _output;
	int div = 0, i;
	unsigned char* buffer;
	unsigned char* changed;

	if (fopen_s(&_output, ENC_FILENAME, "w")){
		printf_s("File save error.\n");
		exit(1);
	}

	make_LOOKUP_TABLE();
	while (div < textSize){
		buffer = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);
		for (i = 0; i < AES_BUFFER; ++i){
			buffer[i] = fgetc(inputFile);
			++div;
		}
		changed = encrypt_AES(buffer, _key);
		for (i = 0; i < AES_BUFFER; ++i) fputc(changed[i], _output);
		free(changed);
	}

	printf("Encryption complete.\n");

	free_LOOKUP_TABLE();
	fclose(inputFile);
	fclose(_output);
}
/******************************/


/********** 복호화 (ECB MODE) **********/
void cipher2plain(unsigned char* _key)
{
	FILE* _output;
	int div = 0, i;
	unsigned char* buffer;
	unsigned char* changed;

	if (fopen_s(&_output, DEC_FILENAME, "w")){
		printf_s("File save error.\n");
		exit(1);
	}

	make_INVERSE_LOOKUP_TABLE();
	while (div < textSize){
		buffer = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);
		for (i = 0; i < AES_BUFFER; ++i){
			buffer[i] = fgetc(inputFile);
			++div;
		}
		changed = decrypt_AES(buffer, _key);
		for (i = 0; i < AES_BUFFER; ++i) fputc(changed[i], _output);
		free(changed);
	}

	printf("Decryption complete.\n");

	free_INVERSE_LOOKUP_TABLE();
	fclose(inputFile);
	fclose(_output);;
}
/******************************/