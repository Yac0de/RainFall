#include <stdio.h>
#include <time.h>

extern char c[68];

void m(void *p1, int p2, char *p3, int p4, int p5) {
    time_t t = time(0);
    printf("%s - %d\n", c, t);
}
