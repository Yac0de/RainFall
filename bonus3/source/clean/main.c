#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char buffer1[66];
    char buffer2[66];
    FILE *file;
    int index;
    
    file = fopen("/home/user/end/.pass", "r");
    
    memset(buffer1, 0, 66);
    
    if (file == NULL || argc != 2) {
        return -1;
    }

    fread(buffer1, 1, 66, file);
    buffer1[65] = '\0';
    
    index = atoi(argv[1]);
    buffer1[index] = '\0';
    
    fread(buffer2, 1, 65, file);
    
    fclose(file);
    
    if (strcmp(buffer1, argv[1]) == 0) {
        execl("/bin/sh", "sh", NULL);
    }
    else {
        puts(buffer2);
    }
    
    return 0;
}
