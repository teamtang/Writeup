---
title: Easy_KeygenMe
date: 2018-11-03 11:24:22
tags: ctf
---

# wp-Easy-KeygenMe
题目链接：[http://reversing.kr/download.php?n=2](http://reversing.kr/download.php?n=2)


**先看题目描述：**
![](http://pdt2ibwo5.bkt.clouddn.com/201811031129_491.png)
给出的序列号是一个线索，需要通过这个序列号找到对应的用户名。

**尝试运行程序看看程序的流程：**
![](http://pdt2ibwo5.bkt.clouddn.com/201811031131_267.png)
可以看到程序逻辑很简单，输入Name和Serial，然后程序会给出判断结果，很容易猜到，如果我们输入的Name和Serial对应的话，那么应该会输出correct。  
这里有一个小窍门，如果你直接双击运行程序，在输出结果之后程序窗口会马上退出，就看不到结果了，这个时候就可以用命令行来运行程序来避免这种情况。

**然后用IDA反编译：**
![](http://pdt2ibwo5.bkt.clouddn.com/201811031134_466.png)
程序的逻辑：  
1. 读入用户输入的Name，将其每个字符循环和v6、v7、v8异或，并将结果**以16进制形式存入**数组v13中
2. 比较处理后的Name和输入的Serial进行比较，如果相同就输出correct，否则输出wrong。

这道题目很简单，需要注意的点就是异或后的结果是以16进制存储到字符数组中的，而不是以字符的形式。

这里附上解题脚本和结果证明：
```Python
str = "\x5B\x13\x49\x77\x13\x5E\x7D\x13"
operand = [16, 32, 48]
for i in range(0, len(str)):
    print(chr(ord(str[i])^operand[i%3]), end='')
```
![](http://pdt2ibwo5.bkt.clouddn.com/201811031140_124.png)