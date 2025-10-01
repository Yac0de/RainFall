#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int return_value;
  char buffer[40];
  int count;
  
  count = atoi(argv[1]);
  
  if (count < 10) {
    memcpy(buffer, argv[2], count * 4);
    
    if (count == 0x574f4c46)
      execl("/bin/sh", "sh", NULL);
    
    return_value = 0;
  }
  else
    return_value = 1;
  
  return return_value;
}
