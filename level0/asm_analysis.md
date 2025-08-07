# Level0 - ASM Analysis (GDB only)

## Introduction

This file complements the main walkthrough.md by providing a low-level analysis of the level0 binary using GDB only, without relying on Ghidra.

We examine how the binary processes its input, makes security checks, and executes a shell. This analysis is useful for understanding how privilege escalation is implemented and under what conditions it is triggered.

---

## Disassemble `main`

We begin by disassembling the `main` function using GDB:

```bash
$ gdb ./level0
(gdb) disas main
```

Dump of assembler code for function `main`:

```asm
0x08048ec0 <+0>:     push   %ebp
0x08048ec1 <+1>:     mov    %esp,%ebp
0x08048ec3 <+3>:     and    $0xfffffff0,%esp
0x08048ec6 <+6>:     sub    $0x20,%esp
```

<+0> to <+6> : Standard function prologue.

* <+0>: Save old base pointer.&#x20;

* <+1>: Set new base pointer.

* <+3>: Align ESP to 16 bytes.

* <+6>: Reserve 32 bytes for local variables.

```asm
0x08048ec9 <+9>:     mov    0xc(%ebp),%eax
0x08048ecc <+12>:    add    $0x4,%eax
0x08048ecf <+15>:    mov    (%eax),%eax
0x08048ed1 <+17>:    mov    %eax,(%esp)
0x08048ed4 <+20>:    call   0x8049710 <atoi>
```

<+9> to <+20> : Convert first argument to integer.

* <+9>: Load pointer to `argv` into EAX.
* <+12>: Move to `argv[1]` by skipping `argv[0]`.
* <+15>: Dereference to get the string content.
* <+17>: Store it on the stack.
* <+20>: Call `atoi(argv[1])`.

```asm
0x08048ed9 <+25>:    cmp    $0x1a7,%eax
0x08048ede <+30>:    jne    0x8048f58 <main+152>
```

<+25> to <+30> : Check if the argument is 423.

* <+25>: Compare result of `atoi()` with 0x1a7.
* <+30>: Jump to error handler if not equal.

```asm
0x08048ee0 <+32>:    movl   $0x80c5348,(%esp)
0x08048ee7 <+39>:    call   0x8050bf0 <strdup>
0x08048eec <+44>:    mov    %eax,0x10(%esp)
0x08048ef0 <+48>:    movl   $0x0,0x14(%esp)
```

<+32> to <+48> : Prepare argument for launching shell.

* <+32>: Push address of "/bin/sh" onto stack.
* <+39>: Duplicate it using `strdup()`.
* <+44>: Store pointer in local stack variable.
* <+48>: Set next argument pointer to NULL (end of argv).

```asm
0x08048ef8 <+56>:    call   0x8054680 <getegid>
0x08048efd <+61>:    mov    %eax,0x1c(%esp)
0x08048f01 <+65>:    call   0x8054670 <geteuid>
0x08048f06 <+70>:    mov    %eax,0x18(%esp)
```

<+56> to <+70> : Save EGID and EUID.

* <+56>: Get effective group ID.
* <+61>: Store it on the stack.
* <+65>: Get effective user ID.
* <+70>: Store it on the stack.

```asm
0x08048f0a <+74>:    mov    0x1c(%esp),%eax
0x08048f0e <+78>:    mov    %eax,0x8(%esp)
0x08048f12 <+82>:    mov    0x1c(%esp),%eax
0x08048f16 <+86>:    mov    %eax,0x4(%esp)
0x08048f1a <+90>:    mov    0x1c(%esp),%eax
0x08048f1e <+94>:    mov    %eax,(%esp)
0x08048f21 <+97>:    call   0x8054700 <setresgid>
```

<+74> to <+97> : Set all GID fields to EGID using `setresgid()`.

```asm
0x08048f26 <+102>:   mov    0x18(%esp),%eax
0x08048f2a <+106>:   mov    %eax,0x8(%esp)
0x08048f2e <+110>:   mov    0x18(%esp),%eax
0x08048f32 <+114>:   mov    %eax,0x4(%esp)
0x08048f36 <+118>:   mov    0x18(%esp),%eax
0x08048f3a <+122>:   mov    %eax,(%esp)
0x08048f3d <+125>:   call   0x8054690 <setresuid>
```

<+102> to <+125> : Set all UID fields to EUID using `setresuid()`.

```asm
0x08048f42 <+130>:   lea    0x10(%esp),%eax
0x08048f46 <+134>:   mov    %eax,0x4(%esp)
0x08048f4a <+138>:   movl   $0x80c5348,(%esp)
0x08048f51 <+145>:   call   0x8054640 <execv>
```

<+130> to <+145> : Execute shell.

* <+130>: Get pointer to argument array.
* <+134>: Set it as second argument to `execv()`.
* <+138>: Set first argument to "/bin/sh".
* <+145>: Call `execv()` to spawn shell.

```asm
0x08048f56 <+150>:   jmp    0x8048f80 <main+192>
```

<+150>: Skip error handling and go to return.

```asm
0x08048f58 <+152>:   mov    0x80ee170,%eax
0x08048f5d <+157>:   mov    %eax,%edx
0x08048f5f <+159>:   mov    $0x80c5350,%eax
0x08048f64 <+164>:   mov    %edx,0xc(%esp)
0x08048f68 <+168>:   movl   $0x5,0x8(%esp)
0x08048f70 <+176>:   movl   $0x1,0x4(%esp)
0x08048f78 <+184>:   mov    %eax,(%esp)
0x08048f7b <+187>:   call   0x804a230 <fwrite>
```

<+152> to <+187> : Print error message using `fwrite()`.

* <+152>: Get stderr pointer.
* <+157>: Move it into EDX.
* <+159>: Load string "No !\n".
* <+164–184>: Prepare arguments for fwrite(buffer, size=1, count=5, stderr.
* <+187>: Call `fwrite()`.

```asm
0x08048f80 <+192>:   mov    $0x0,%eax
0x08048f85 <+197>:   leave
0x08048f86 <+198>:   ret
```

<+192> to <+198> : Return normally from main.

---

Next step: we will inspect this logic live using GDB to confirm memory contents, arguments, and syscall behavior.

---

## Observing the Binary's Behavior in GDB

This section demonstrates how to use GDB to confirm what the binary is doing during execution. By setting breakpoints at key instructions and inspecting memory or registers, we can understand how the shell gets launched.

### Inspecting atoi(argv\[1])

We start by checking how the argument is interpreted as an integer:

```gdb
(gdb) break *0x08048ed4         # Before atoi is called
(gdb) run 423
```

Once hit:

```gdb
(gdb) x/s *((char **)($esp))    # Display argv[1]
0xbffff8f8: "423"
```

This confirms that the argument is indeed passed correctly to `atoi()`.

### Inspecting the Comparison to 0x1a7 (423 in decimal)

To verify the control flow depending on the input value:

```gdb
(gdb) break *0x08048ed9         # cmp $0x1a7, %eax
(gdb) continue
(gdb) print $eax                # Check result of atoi
$1 = 423
```

The comparison is passed, and execution proceeds to privilege escalation.

### If matched, sets UID/GID via setresuid() / setresgid()

We now confirm that the binary sets UID and GID if the input is correct:

```gdb
(gdb) break *0x08048f21         # Before setresgid is called
(gdb) continue
(gdb) print $eax                # EGID passed to syscall
$2 = 2020

(gdb) break *0x08048f3d         # Before setresuid is called
(gdb) continue
(gdb) print $eax                # EUID passed to syscall
$3 = 2020
```

Note: These are the values returned by `getegid()` and `geteuid()`, which are then passed into the syscalls. They correspond to the effective UID/GID of the binary’s file owner (`level1`) due to the SUID bit, not the user executing it.

To confirm that the privilege change actually took place:

```bash
$ ./level0 423
$ id
uid=2030(level1) gid=2020(level0) groups=2030(level1),100(users),2020(level0)
```

### Inspecting execv("/bin/sh", ...)

To confirm that the binary launches a shell:

```gdb
(gdb) break *0x08048f51         # Before execv is called
(gdb) continue
(gdb) x/s *(char **)($esp)     # First argument to execv
0x80c5348: "/bin/sh"

(gdb) x/s *(char **)($esp+4)   # Second argument to execv (argv)
0xbffff720: "\030'\017\b"      # This is not a string, but a pointer to argv[0] ("/bin/sh")

(gdb) x/xw $esp+4              # Check the value at $esp+4
0xbffff714:     0xbffff720     # Points to the argv[] array

(gdb) x/xw 0xbffff720          # Dereference first element
0xbffff720:     0x080f2718

(gdb) x/s 0x080f2718            # Finally, get the actual string
0x80c5348: "/bin/sh"
```

We observe the binary prepares a proper call to spawn a shell.

### When input is incorrect

To see what happens if the input is not 423:

```gdb
(gdb) break *0x08048f7b         # fwrite call
(gdb) run 1
(gdb) x/s 0x80c5350             # Error message
0x80c5350: "No !\n"
```

This confirms that incorrect input leads to an error message without any privilege change.

---

## Conclusion

Using GDB, we confirmed that the binary:

* Converts input via `atoi()`
* Compares it to a hardcoded value (0x1a7)
* If matched, sets UID/GID via `setresuid()` / `setresgid()`
* Then executes `/bin/sh`

This results in a shell with elevated privileges when invoked with `./level0 423`.

This approach shows the full privilege escalation logic without relying on any static reverse engineering tool.

