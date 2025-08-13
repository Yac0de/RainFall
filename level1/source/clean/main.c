#include <stdio.h>

char *gets(char *);

int main(void) {
    char buf[76];

    gets(buf);
    return(0);
}
