#include "aes.h"
#include "fileHandle.h"

int main(int argc, unsigned char** argv)
{
	unsigned char tempChar;
	unsigned char key[KEY_LENGTH];

	int tempTime2;

	/********** ���� ó�� **********/
	fileOpenCheck(argc, argv);
	fileSizeCheck();
	copyKeyFile(key);
	/******************************/

	/********** ����, �����ڽ�, Ű Ȯ��, ��� ���̺� ���� **********/
	make_RCON();
	make_S_BOX();
	memoExpendedKeys(key);
	/******************************/

	/********** ���ϴ� ��带 �Է� �ް� ���� �� ���� **********/
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