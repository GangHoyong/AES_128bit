#include "aes.h"
#include "fileHandle.h"

int main(int argc, unsigned char** argv)
{
	unsigned char tempChar;
	unsigned char key[KEY_LENGTH];

	int tempTime2;

	/********** 파일 처리 **********/
	fileOpenCheck(argc, argv);
	fileSizeCheck();
	copyKeyFile(key);
	/******************************/

	/********** 알콘, 에스박스, 키 확장, 룩업 테이블 생성 **********/
	make_RCON();
	make_S_BOX();
	memoExpendedKeys(key);
	/******************************/

	/********** 원하는 모드를 입력 받고 수행 후 저장 **********/
	do{
		printf_s("Please press the key if you want to make the file \'encrypted(e) / decrypted(d)\'.\nYour selection : ");
		scanf_s("%c", &tempChar, 1);

		switch (tempChar){
		case 'e':
		case 'E':
			plain2cipher(key);
			goto _EXIT;

		case 'd':
		case 'D':
			cipher2plain(key);
			goto _EXIT;

		default:
			printf("Press just 'e','E','d' or 'D' key.\n");
			fflush(stdin);
		}
	} while (1);
	/******************************/

_EXIT:
	return 0;
}