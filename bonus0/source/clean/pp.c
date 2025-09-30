#include <string.h>

char *p(char *s, char *str);

char *pp(char *buffer)
{
    char            b[20];
    char            a[20];
    unsigned int    len;

    p(a, " - ");
    p(b, " - ");
    strcpy(buffer, a);
    len = strlen(buffer);
    buffer[len] = ' ';
    buffer[len + 1] = 0;
    return (strcat(buffer, b));
}

