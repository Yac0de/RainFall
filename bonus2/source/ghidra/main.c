undefined4 main(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  char *pcVar3;
  undefined4 *puVar4;
  byte bVar5;
  char local_60 [40];
  char acStack_38 [36];
  char *local_14;
  
  bVar5 = 0;
  if (param_1 == 3) {
    pcVar3 = local_60;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      pcVar3[0] = '\0';
      pcVar3[1] = '\0';
      pcVar3[2] = '\0';
      pcVar3[3] = '\0';
      pcVar3 = pcVar3 + 4;
    }
    strncpy(local_60,*(char **)(param_2 + 4),0x28);
    strncpy(acStack_38,*(char **)(param_2 + 8),0x20);
    local_14 = getenv("LANG");
    if (local_14 != (char *)0x0) {
      iVar2 = memcmp(local_14,&DAT_0804873d,2);
      if (iVar2 == 0) {
        language = 1;
      }
      else {
        iVar2 = memcmp(local_14,&DAT_08048740,2);
        if (iVar2 == 0) {
          language = 2;
        }
      }
    }
    pcVar3 = local_60;
    puVar4 = (undefined4 *)&stack0xffffff50;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *(undefined4 *)pcVar3;
      pcVar3 = pcVar3 + ((uint)bVar5 * -2 + 1) * 4;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
    uVar1 = greetuser();
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
