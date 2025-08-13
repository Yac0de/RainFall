#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth;
char *service;

int main(void) {
    char buf[128];

    while (1) {
        printf("%p, %p \n", auth, service);

        if (!fgets(buf, 128, stdin))
            return 0;

        if (!strncmp(buf, "auth ", 5)) {
            auth = (char *)malloc(4);
            auth[0] = '\0';
            auth[1] = '\0';
            auth[2] = '\0';
            auth[3] = '\0';
            if (strlen(buf + 5) < 31)
                strcpy(auth, buf + 5);
        }

        if (!strncmp(buf, "reset", 5)) {
            free(auth);
        }

        if (!strncmp(buf, "service", 6)) {
            service = strdup(buf + 7);
        }

        if (!strncmp(buf, "login", 5)) {
            if (*(int *)(auth + 32) == 0)
                fwrite("Password:\n", 1, 10, stdout);
            else
                system("/bin/sh");
        }
    }
}
