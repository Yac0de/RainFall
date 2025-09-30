#include <stdio.h>

char *pp(char *buffer);

int main(void)
{
    char buffer[42];

    pp(buffer);
    puts(buffer);
    return (0);
}

