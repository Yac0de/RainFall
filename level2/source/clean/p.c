#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

char *gets(char *);

void p(void) {
    char buf[76];

    fflush(stdout);
    gets(buf);

    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if ((ra & 0xb0000000u) == 0xb0000000u) {
        printf("(%p)\n", (void*)ra);
        _exit(1);
    }

    puts(buf);
    (void)strdup(buf);
}
