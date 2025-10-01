#include <stdio.h>

int main()
{
	long i = 0;

	for (;;)
	{
		if ((int)i * 4 == 44)
		{
			printf("i=%ld i*4=%d\n", i, (int)i*4);
			return 0;
		}
		i--;
	}
}
