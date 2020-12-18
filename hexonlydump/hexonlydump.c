#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EndOfFile 0xffffffff

int help(char* binary)
{
    printf("[*] Example: %s [file]\n", binary);
    return 1;
}


int main(int argc, char* argv[])
{
    /* Check argc length */
    if (argc != 2) return help(argv[0]);
    /* Check argv help */
    if (!strncmp(argv[1], "--help", 6) || !strncmp(argv[1], "-h", 2)) return help(argv[0]);

    const char* file_args = argv[1];
    /* Read input file */
    FILE* file = fopen(file_args, "r");
    /* VAR contains the chr */
    unsigned int chr;

    /* WRITE hexa char to stdout */
    while ((chr = fgetc(file)) != EndOfFile)
    {
        if (chr < 0xb) printf("0");
        printf("%x ", chr);
    }
    /* new line */
    printf("\n");
    return 0;
}