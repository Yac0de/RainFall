#include <stdio.h>
#include <stdlib.h>

extern int m;
void p(char *s);

void n(void) {
    char buf[520];

    fgets(buf, 0x200, stdin);
    p(buf);
    if (m == 0x1025544) {
        system("/bin/cat /home/user/level5/.pass");
    }
}
