#include "aes.h"
#include "galoisField.h"


unsigned char MIX_COLUMNS_MATRIX[ELEMENT_MIX_COLUMNS_MATRIX][ELEMENT_MIX_COLUMNS_MATRIX] = {
		{ 0x2, 0x3, 0x1, 0x1 },
		{ 0x1, 0x2, 0x3, 0x1 },
		{ 0x1, 0x1, 0x2, 0x3 },
		{ 0x3, 0x1, 0x1, 0x2 }
};

unsigned char INVERSE_MIX_COLUMNS_MATRIX[ELEMENT_MIX_COLUMNS_MATRIX][ELEMENT_MIX_COLUMNS_MATRIX] = {
		{ 0xE, 0xB, 0xD, 0x9 },
		{ 0x9, 0xE, 0xB, 0xD },
		{ 0xD, 0x9, 0xE, 0xB },
		{ 0xB, 0xD, 0x9, 0xE },
};


/********** AES 암호화 **********/
unsigned char* encrypt_AES(unsigned char* _buf, unsigned char* _key)
{
	int _round;
	unsigned char* _chgd;

	_chgd = addRoundKey(_buf, _key);
	for (_round = 0; _round < NUM_ROUND - 1; ++_round){	// 1 ~ 9 라운드
		_chgd = addRoundKey(referLookupTable(_chgd), roundKey[_round]);
	}

	return addRoundKey(substituteByte_shiftRows(_chgd), roundKey[NUM_ROUND - 1]);	// 10 라운드
}
/******************************/


/********** AES 복호화 **********/
unsigned char* decrypt_AES(unsigned char* _buf, unsigned char* _key)
{
	int round;
	unsigned char* _chgd;

	_chgd = inverse_substituteByte_shiftRows(addRoundKey(_buf, roundKey[NUM_ROUND - 1]));
	for (round = 1; round < NUM_ROUND; ++round)
		_chgd = inverse_referLookupTable(addRoundKey(_chgd, roundKey[NUM_ROUND - round - 1]));

	return addRoundKey(_chgd, _key);
}
/******************************/


/********** RCON 만들기 **********/
void make_RCON()
{
	int i;
	unsigned int temp;

	RCON = (unsigned char*)malloc(sizeof(unsigned char) * NUM_ROUND);
	RCON[0] = 1;
	for (i = 1; i < NUM_ROUND; ++i){
		if ((temp = RCON[i - 1] << 1) > 0xFF){
			devideByte(temp, MOD_POLYNOMIAL);
			RCON[i] = RMD;
		}
		else
			RCON[i] = (unsigned char)temp;
	}
}
/******************************/


/********** S-BOX 만들기 **********/
void make_S_BOX()
{
	unsigned int _sequence;
	unsigned char _sequenceInverse;

	for (_sequence = 0; _sequence < ELEMENT_S_BOX; ++_sequence){
		_sequenceInverse = calc_inverseByte(_sequence);
		S_BOX[_sequence] = calc_S_MATRIX(_sequenceInverse);
		INVERSE_S_BOX[S_BOX[_sequence]] = _sequence;
	}
}
/******************************/


/********** 인버스 구하기 (Extended Euclide Algorithm) **********/
unsigned char calc_inverseByte(unsigned char _byte)
{
	unsigned int preRemainder = MOD_POLYNOMIAL, nextRemainder = _byte, preAuxiliary = 0, nextAuxiliary = 1, temp;
	
	if (!_byte) return _byte;
	while (nextRemainder != 1){
		devideByte(preRemainder, nextRemainder);
		preRemainder = nextRemainder;
		nextRemainder = RMD;
		temp = nextAuxiliary;
		nextAuxiliary = multiplyByte(nextAuxiliary, QUO) ^ preAuxiliary;
		preAuxiliary = temp;
	}

	return (unsigned char)nextAuxiliary;
}
/******************************/


/********** S-BOX 만드는 과정 (행렬곱과 바이트 합) **********/
unsigned char calc_S_MATRIX(unsigned char _invByte)
{
	int numSet, i, j;
	unsigned char matrix = S_MATRIX, resProduct, resCalc = 0;

	for (i = 0; i < BYTESIZ; ++i){
		numSet = 0;
		resProduct = _invByte & matrix;	// 행렬곱 AND 연산

		for (j = 0; j < BYTESIZ; ++j){
			if (resProduct & 1)	++numSet;
			resProduct >>= 1;
		}

		if (numSet & 1)	resCalc |= (1 << i);	// 1의 짝,홀수에 따라 Bit SET
		__asm{ rol matrix, 1 }	// 다음 행을 위한 Rotate
	}

	return resCalc ^ S_ADD_BYTE;	// 0x63을 XOR 연산 후 리턴
}
/******************************/


/********** 룩업 테이블 참고 **********/
unsigned char* referLookupTable(unsigned char* _buf)
{
	int h, i, j, k, cnt = 0;
	unsigned char* _chgd = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);

	for (h = 0; h < ELEMENT_MIX_COLUMNS_MATRIX; ++h){
		for (i = 0; i < ELEMENT_MIX_COLUMNS_MATRIX; ++i){
			k = h << 2;
			_chgd[cnt] = 0;
			for (j = 0; j < 4; ++j){
				_chgd[cnt] ^= LOOKUP_TABLE[i][j][_buf[k]];
				k = (k + 5) & (AES_BUFFER - 1);
			}
			++cnt;
		}
	}

	free(_buf);
	return _chgd;
}
/******************************/


/********** 에스박스 치환과 쉬프트로우를 동시 수행 **********/
unsigned char* substituteByte_shiftRows(unsigned char* _buf)
{
	int i, j, k, cnt = 0;
	unsigned char* _chgd = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);

	for (i = 0; i < 4; ++i){
		k = i << 2;
		for (j = 0; j < 4; ++j){
			_chgd[cnt++] = S_BOX[_buf[k]];
			k = (k + 5) & (AES_BUFFER - 1);
		}
	}

	free(_buf);
	return _chgd;
}
/******************************/


/********** 애드 라운드 키 **********/
unsigned char* addRoundKey(unsigned char* _buf, unsigned char* _roundKey)
{
	int i = 0;
	unsigned char* _chgd = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);

	while (i < AES_BUFFER){
		_chgd[i] = _buf[i] ^ _roundKey[i];
		++i;
	}

	free(_buf);
	return _chgd;
}
/******************************/


/********** 키 확장 **********/
unsigned char* keyExpension(int _round, unsigned char* _preRound)
{
	int i, j, k;
	unsigned char* lastBytes;
	unsigned char* _extKey = (unsigned char*)malloc(sizeof(unsigned char) * KEY_LENGTH);


	lastBytes = R_function(_round, _preRound + 12);
	for (i = 0; i < 4; ++i)
		_extKey[i] = lastBytes[i] ^ _preRound[i];

	for (i = 1; i < 4; ++i)
	{
		k = i << 2;
		for (j = 0; j < 4; ++j)
			_extKey[k + j] = _extKey[k + j - 4] ^ _preRound[k + j];
	}

	free(lastBytes);
	return _extKey;
}
/******************************/


/********** 키 확장한 후 저장 **********/
void memoExpendedKeys(unsigned char* _origKey)
{
	int _round, j;
	unsigned char* _key;

	_key = keyExpension(0, _origKey);
	for (j = 0; j < KEY_LENGTH; ++j) roundKey[0][j] = _key[j];	// 1라운드
	for (_round = 1; _round < NUM_ROUND; ++_round){	// 2~10라운드
		_key = keyExpension(_round, roundKey[_round - 1]);
		for (j = 0; j < KEY_LENGTH; ++j) roundKey[_round][j] = _key[j];
	}

	free(RCON);
}
/******************************/


/********** 키 확장 (R 함수) **********/
unsigned char* R_function(int _round, unsigned char* last)
{
	unsigned char* resFunc = (unsigned char*)malloc(sizeof(unsigned char) << 2);

	resFunc[0] = S_BOX[last[1]] ^ RCON[_round];
	resFunc[1] = S_BOX[last[2]];
	resFunc[2] = S_BOX[last[3]];
	resFunc[3] = S_BOX[last[0]];

	return resFunc;
}
/******************************/


/********** 인버스 룩업 테이블 참고 **********/
unsigned char* inverse_referLookupTable(unsigned char* _buf)
{
	int h, i, j, k;
	unsigned char* _chgd = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);

	for (h = 0; h < ELEMENT_MIX_COLUMNS_MATRIX; ++h){
		k = h << 2;
		for (i = 0; i < ELEMENT_MIX_COLUMNS_MATRIX; ++i){
			_chgd[k] = 0;
			for (j = 0; j < 4; ++j)	_chgd[k] ^= INVERSE_LOOKUP_TABLE[i][j][_buf[(h << 2) + j]];
			_chgd[k] = INVERSE_S_BOX[_chgd[k]];
			k = (k + 5) & (AES_BUFFER - 1);
		}
	}

	free(_buf);
	return _chgd;
}
/******************************/


/********** 인버스 에스박스 치환과 인버스 쉬프트로우를 동시 수행 **********/
unsigned char* inverse_substituteByte_shiftRows(unsigned char* _buf)
{
	int i, j, k, cnt = 0;
	unsigned char* _chgd = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);

	for (i = 0; i < 4; ++i){
		k = ((i << 2) | 0x100) & (AES_BUFFER - 1);
		for (j = 0; j < 4; ++j){
			_chgd[cnt++] = INVERSE_S_BOX[_buf[k]];
			k = (k - 3) & (AES_BUFFER - 1);
		}
	}

	free(_buf);
	return _chgd;
}
/******************************/


/********** 인버스 치환 **********/
unsigned char* inverese_substituteByte(unsigned char* _buf)
{
	int i;
	unsigned char* _chgd = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);

	for (i = 0; i < KEY_LENGTH; ++i)
		_chgd[i] = INVERSE_S_BOX[_buf[i]];

	free(_buf);
	return _chgd;
}
/******************************/


/********** 인버스 쉬프트로우, 방향을 거꾸로 **********/
unsigned char* inverese_shiftRows(unsigned char* _buf)
{
	int i, j, k, cnt = 0;
	unsigned char* _chgd = (unsigned char*)malloc(sizeof(unsigned char) * AES_BUFFER);

	for (i = 0; i < 4; ++i){
		k = (i << 2) | 0x100;
		for (j = 0; j < 4; j++){
			_chgd[cnt++] = _buf[k & (AES_BUFFER - 1)];
			k -= 3;
		}
	}

	free(_buf);
	return _chgd;
}
/******************************/


/********** 룩업 테이블 생성 **********/
void make_LOOKUP_TABLE()
{
	int i = 0, j, k;

	LOOKUP_TABLE = (unsigned char***)malloc(sizeof(unsigned char**) * ELEMENT_MIX_COLUMNS_MATRIX);
	for (; i < ELEMENT_MIX_COLUMNS_MATRIX; ++i){
		LOOKUP_TABLE[i] = (unsigned char**)malloc(sizeof(unsigned char*) * ELEMENT_MIX_COLUMNS_MATRIX);
		for (j = 0; j < ELEMENT_MIX_COLUMNS_MATRIX; ++j){
			LOOKUP_TABLE[i][j] = (unsigned char*)malloc(sizeof(unsigned char) * ELEMENT_S_BOX);
			for (k = 0; k < ELEMENT_S_BOX; ++k)
				LOOKUP_TABLE[i][j][k] = multiplyByte(MIX_COLUMNS_MATRIX[i][j], S_BOX[k]);
		}
	}	
}
/******************************/


/********** 인버스 룩업 테이블 생성 **********/
void make_INVERSE_LOOKUP_TABLE()
{
	int i = 0, j, k;

	INVERSE_LOOKUP_TABLE = (unsigned char***)malloc(sizeof(unsigned char**) * ELEMENT_MIX_COLUMNS_MATRIX);
	for (; i < ELEMENT_MIX_COLUMNS_MATRIX; ++i){
		INVERSE_LOOKUP_TABLE[i] = (unsigned char**)malloc(sizeof(unsigned char*) * ELEMENT_MIX_COLUMNS_MATRIX);
		for (j = 0; j < ELEMENT_MIX_COLUMNS_MATRIX; ++j){
			INVERSE_LOOKUP_TABLE[i][j] = (unsigned char*)malloc(sizeof(unsigned char) * ELEMENT_S_BOX);
			for (k = 0; k < ELEMENT_S_BOX; ++k)
				INVERSE_LOOKUP_TABLE[i][j][k] = multiplyByte(INVERSE_MIX_COLUMNS_MATRIX[i][j], k);
		}
	}

}
/******************************/


/********** 룩업 테이블 해제 **********/
void free_LOOKUP_TABLE()
{
	int i = 0, j;

	for (; i < ELEMENT_MIX_COLUMNS_MATRIX; ++i){
		for (j = 0; j < ELEMENT_MIX_COLUMNS_MATRIX; ++j) free(LOOKUP_TABLE[i][j]);
		free(LOOKUP_TABLE[i]);
	}

	free(LOOKUP_TABLE);
}
/******************************/


/********** 인버스 룩업 테이블 해제 **********/
void free_INVERSE_LOOKUP_TABLE()
{
	int i = 0, j;

	for (; i < ELEMENT_MIX_COLUMNS_MATRIX; ++i){
		for (j = 0; j < ELEMENT_MIX_COLUMNS_MATRIX; ++j) free(INVERSE_LOOKUP_TABLE[i][j]);
		free(INVERSE_LOOKUP_TABLE[i]);
	}

	free(INVERSE_LOOKUP_TABLE);
}
/******************************/