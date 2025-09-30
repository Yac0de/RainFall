#include <stdio.h>
#include <string.h>
#include <unistd.h>

char *p(char *s, char *str)
{
    char buffer[4096];

    puts(str);
    read(0, buffer, 4096);
    *strchr(buffer, '\n') = 0;
    return (strncpy(s, buffer, 20));
}

