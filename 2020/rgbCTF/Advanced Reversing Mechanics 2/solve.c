#include <string.h>
#include <stdio.h>

void  encryptFlag(unsigned long arg1)
{
    int iVar1;
    unsigned char *puVar2;
    unsigned char *puVar3;
    unsigned char uVar4;
    unsigned char uVar5;
    
    iVar1 = 0x66666667;
    // [01] -r-x section size 168 named .text
    uVar4 = *(unsigned char *)arg1;
    puVar3 = (unsigned char *)arg1;
    if (uVar4 == 0) {
        return;
    }
    while( 1 ) {
        uVar5 = uVar4;
        if ((uVar4 < 0x50) && (uVar5 = uVar4 - 10, 0x50 < (unsigned char)(uVar4 - 10))) {
            uVar5 = uVar4 + 0x46;
        }
        uVar4 = uVar5 - 7 ^ 0x43;
        puVar2 = puVar3 + 1;
        *puVar3 = uVar4 << 6 | uVar4 >> 2;
        uVar4 = *puVar2;
        puVar3 = puVar2 -arg1;
        if (uVar4 == 0) break;
        puVar3 = puVar3 + ((int)((long)iVar1 * (long)(int)puVar3 >> 0x21) - ((int)puVar3 >> 0x1f)) *
                          -5;
        uVar4 = uVar4 << (-(int)puVar3 & 7U) | uVar4 >> ((unsigned int)puVar3 & 0xff);
        if (puVar3 == (unsigned char *)0x2) {
            uVar4 = uVar4 - 1;
        }
        *puVar2 = uVar4;
        uVar4 = *puVar2;
        puVar3 = puVar2;
    }
    return;
}

int main(int argc, char const *argv[])
{
	char flag[36], sol[36];
	const char *enc = "\x0A\xFB\xF4\x88\xDD\x9D\x7D\x5F\x9E\xA3\xC6\xBA\xF5\x95\x5D\x88\x3B\xE1\x31\x50\xC7\xFA\xF5\x81\x99\xC9\x7C\x23\xA1\x91\x87\xB5\xB1\x95\xE4";
	// scanf("%s", flag);
	// encryptFlag((unsigned long)flag);

	// printf("%s", flag);

	for (int j = 0; j < 37; ++j)
	{

		for (int i = 0; i < 256; ++i)
			{
				for (int k = 0; k < 37; ++k)
					flag[k] = sol[k];
				flag[j] = i;
				encryptFlag((unsigned long)flag);
				if (flag[j] == enc[j])
				{
					sol[j] = i;
					break;
				}
			}
	}

	printf("%s\n", sol);



	return 0;
}