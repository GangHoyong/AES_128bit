#include "galoisField.h"


/********** ����ü ������ ����, ���� �� ���� �������� QUO��, �������� �������� RMD�� ���� **********/
void devideByte(unsigned int _lhs, unsigned int _rhs)
{
	int quotient = 0, _lhsMSB, _rhsMSB = 0;

	while ((_rhs >> _rhsMSB) > 0) ++_rhsMSB;
	while (1){
		_lhsMSB = 0;
		while ((_lhs >> _lhsMSB) > 0) ++_lhsMSB;
		if (_rhsMSB > _lhsMSB) break;
		_lhs ^= (_rhs << (_lhsMSB - _rhsMSB));
		quotient |= (1 << (_lhsMSB - _rhsMSB));
	}
	QUO = quotient;
	RMD = _lhs;
}
/******************************/


/********** ����ü �� ���� **********/
unsigned char multiplyByte(unsigned char _lhs, unsigned char _rhs)
{
	unsigned int i = 0, sum = 0, LHS = _lhs;

	for (; i < BYTESIZ; ++i){
		if ((_rhs >> i) & 1)
			sum ^= LHS << i;
	}
	devideByte(sum, MOD_POLYNOMIAL);

	return RMD;
}
/******************************/