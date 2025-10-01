#include <string.h>
#include <stdlib.h>

extern int language;
void greetuser(char *username);

int main(int argc, char **argv)
{
    char buffer1[40];
    char buffer2[32];
    char *lang;
    
    if (argc != 3) {
        return 1;
    }
    
    memset(buffer1, 0, 40);
    memset(buffer2, 0, 32);
    
    strncpy(buffer1, argv[1], 40);
    strncpy(buffer2, argv[2], 32);
    
    lang = getenv("LANG");
    if (lang != NULL) {
        if (memcmp(lang, "fi", 2) == 0) {
            language = 1;
        }
        else if (memcmp(lang, "nl", 2) == 0) {
            language = 2;
        }
    }
    
    strcat(buffer1, buffer2);
    greetuser(buffer1);
    
    return 0;
}
