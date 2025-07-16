## Level 0 Walkthrough

### Who am I?

```bash
level0@RainFall:~$ id
uid=2000(level0) gid=2000(level0) groups=2000(level0)
```

### Where am I?

### Files in this directory

```bash
level0@RainFall:~$ ll
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
```

The directory contains a single SUID binary owned by `level1`. The goal is to escalate privileges and retrieve `/home/user/level1/.pass`.

---

## Step-by-step Exploitation

### 1. Binary behavior

```bash
level0@RainFall:~$ ./level0
Segmentation fault (core dumped)

level0@RainFall:~$ ./level0 test
No !
```

* The binary crashes with no argument.
* It returns "No !" when any argument is provided, unless a specific value is used.

---

### 2. Static analysis using Ghidra

#### What is Ghidra?

[Ghidra](https://ghidra-sre.org/) is a free and open-source reverse engineering tool developed by the NSA. It can disassemble and decompile binaries, making it easier to understand how they work without having access to the original source code.

It is a very useful tool in the context of binary exploitation, as it allows:

* Visualization of assembly code and function calls.
* Rebuilding pseudo-C code from raw machine instructions.

#### How to transfer the binary to your local machine?

To analyze the binary with Ghidra, you first need to copy it from the VM to your host:

```bash
# From your host machine (not inside the VM):
scp -P 4242 level0@<VM_IP>:level0 .
```

Then open Ghidra, create a project, and import the binary for decompilation.

#### Ghidra decompilation output

Below is the actual decompiled output obtained directly from Ghidra:

```c
undefined4 main(undefined4 param_1, int param_2)
{
  int iVar1;
  char *local_20;
  undefined4 local_1c;
  __uid_t local_18;
  __gid_t local_14;

  iVar1 = atoi(*(char **)(param_2 + 4));
  if (iVar1 == 0x1a7) {
    local_20 = strdup("/bin/sh");
    local_1c = 0;
    local_14 = getegid();
    local_18 = geteuid();
    setresgid(local_14, local_14, local_14);
    setresuid(local_18, local_18, local_18);
    execv("/bin/sh", &local_20);
  }
  else {
    fwrite("No !\n", 1, 5, (FILE *)stderr);
  }
  return 0;
}
```

* The binary converts the first argument to an integer.
* If the integer is `0x1a7` (which is 423 in decimal), it sets the real and effective UID/GID to match the current ones (those of the file owner), and then launches a shell.
* Otherwise, it prints an error message.

---

### 3. Exploitation

```bash
level0@RainFall:~$ ./level0 423
$ id
uid=2001(level1) gid=2000(level0) groups=2000(level0)
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

By passing `423` as argument, the program spawns a shell with `level1` privileges, allowing us to read the password.

---

## Files in this repository

```
level1/
├── flag.txt
├── walkthrough.md
└──decompiled_level0/
   └── main.c
```
