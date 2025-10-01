void greetuser(void)

{
  char local_4c [4];
  undefined4 local_48;
  char local_44 [64];
  
  if (language == 1) {
    local_4c[0] = 'H';
    local_4c[1] = 'y';
    local_4c[2] = 'v';
    local_4c[3] = -0x3d;
    local_48._0_1_ = -0x5c;
    local_48._1_1_ = -0x3d;
    local_48._2_1_ = -0x5c;
    local_48._3_1_ = ' ';
    builtin_strncpy(local_44,"päivää ",0xb);
  }
  else if (language == 2) {
    builtin_strncpy(local_4c,"Goed",4);
    local_48._0_1_ = 'e';
    local_48._1_1_ = 'm';
    local_48._2_1_ = 'i';
    local_48._3_1_ = 'd';
    builtin_strncpy(local_44,"dag!",4);
    local_44[4] = ' ';
    local_44[5] = '\0';
  }
  else if (language == 0) {
    builtin_strncpy(local_4c,"Hell",4);
    local_48._0_3_ = 0x206f;
  }
  strcat(local_4c,&stack0x00000004);
  puts(local_4c);
  return;
}
