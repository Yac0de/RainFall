#include <stdlib.h>
#include <unistd.h>

void o(void) {
    system("/bin/sh");
    _exit(1);
}
