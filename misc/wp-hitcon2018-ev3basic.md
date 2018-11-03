---
title: wp-hitcon2018-ev3basic
date: 2018-11-03 16:08:25
tags: ctf
---

自己没有做出来这道题，看了一个其他大佬的wp，感觉写得非常好！

[大佬的writeup](https://github.com/PDKT-Team/ctf/blob/master/hitcon2018/ev3-basic/README.md)



总结一下这类题目的思路：
1. 使用过滤功能从大量的数据包中过滤掉边边角角的信息，留下关键的信息
    过滤方式常见的有：过滤源地址和目的地址、过滤协议
2. 比较筛选出的包中的数据的区别，区别的地方很可能就是我们需要的数据
3. 如果看到了像是flag中的字符，就基本上成功一半了，自己做的时候用wireshark的查找功能查找可能在数据包中的字符串，但是没有找到，原来是要用`Hex value`的模式进行筛选:
![](http://pdt2ibwo5.bkt.clouddn.com/201811031614_929.png)