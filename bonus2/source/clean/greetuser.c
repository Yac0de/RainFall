#include <string.h>
#include <stdio.h>

int language = 0;

void greetuser(char *username)
{
    char greeting[72];
    
    if (language == 1) {
        // Finnish: "Hyvää päivää "
        strcpy(greeting, "Hyvää päivää ");
    }
    else if (language == 2) {
        // Dutch: "Goedemiddag! "
        strcpy(greeting, "Goedemiddag! ");
    }
    else {
        // English: "Hello "
        strcpy(greeting, "Hello ");
    }
    
    strcat(greeting, username);
    puts(greeting);
}
