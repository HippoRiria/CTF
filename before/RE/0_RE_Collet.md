## 1.Hello,CTF

逆向经典套餐，查壳IDAOD一条龙。

可惜这个IDA开Strings窗口就看到了，写个脚本解密就行。

springf内可看到转换字符。

转换字符一览：

%% 印出百分比符号，不转换        %c 整数转ascii

%d 整数转十进制                            %f 倍精确度数字转浮点数

%o 整数转八进制							%s 整数转字符串

%x 整数转小写十六进制                 %X 整数转大写十六进制



经验：IDA是神。另外这个转换字符可以和base64这些出misc题。



## 2.happyctf

逆向套餐，IDA写脚本，OD下断点拦截。唯一难点是有轻微的混淆。



经验：耐心是宝贵的美德。



## 3.76号

查壳，发现是ELF文件。

IDA，看到Strings里有字符串，跟踪。

分析代码，发现有自增变量在填充 flag 字符串，追着自增变量一步步复原flag



经验：耐心，兄弟



## 4.1000Click

启动，要我点一千次才出flag，傻逼才点

OD，改相关数值。甚至连数值也不用改，插件一查直接有flag了。



经验：没啥营养的题目



## 5.answer_to_everything

ELF文件

IDA，然后有提示要用sha1加密，flag就是sha1加密后的字符串。



经验：需要去学下Linux的操作方式了。



## 6.BabyXor

UPolyx壳，ESP定律脱。

IDA分析也行，但这题OD查内存更快。

写脚本时注意一下原程序的逻辑细节，如起始区域。



经验：耐心+仔细，啥题都能理出一些步骤。



## 7.crackme

nsPack壳，有相关工具可以脱，没有收录此工具。

也可以手工脱壳，OD+ESP定律即可。

先找pushad和pushfd作为OEP（程序入口点），然后F8找到第一次ESP变化位置，给ESP设断点。最后F9去找JMP。JMP位置就是程序本身的入口点。

最后用PETools来修改IAT以及入口点即可。

参考https://blog.csdn.net/qq_42967398/article/details/94761189



最后IDA静态分析，直接F5，伪代码反写就行。密文数组需要查下dword具体位置。



经验：ESP定律的实际应用，很多简单壳可以这样脱。PETools工具到手！



## 8.debug

.NET 文件的分析，使用工具dnSpy进行分析。另外还有工具 LISpy也可以用于分析。

dnspy支持动态调试，先看代码理清顺序，然后下断点截下flag字符串。



经验：分析.NET工具 dnSpy 到手



## 9.EASYHOOK

查壳先，无壳。

先静态分析，很容易就能找到疑似flag的文件。但真把它当flag就上当了！

多说无益，静态分析找的就是自定义函数。一个个把主函数里的自定义函数都看一遍。题目提示了Hook，Hook是啥？是修改了CPU代码执行次序的东西。

有Hook，就得看Read&Write组合，重点看Write写了什么。顺着这个思路可以找到writefile函数里进行了发生了修改，跳转到了另一个函数。

很不巧，跳转函数正好是加密函数。

然后就是代码反写了。



经验：程序带Hook的情况不太好判断，如果没有提示需要多观察汇编中的R&W组合。



## 10.game

额，玩游戏，但这个游戏理论似乎解不了。

OD改数值就行

IDA的还没看，似乎有简单的异或加密，也不算太难。



经验：CTF和实战的不同之处在此，实战直接Hook就行，CTF得理一理逻辑。



## 11.IgniteMe

查壳，无壳。

IDA分析，F5神器。很快就找到main。

理清逻辑，找到加密函数。

顺着byte找到加密后的flag。

最后反写即可。



经验：找加密函数，找加密后字符都得养成习惯。



## 12.Mysterious

IDA+F5，can can 伪代码。

分析一下就知道flag中的几个部分由ASCII组成，然后写就完事了。



经验：签到题都不如



## 13.python_trade

下载下来是一个pyc文件，啥玩意？先去查查资料

pyc文件是python.exe编译py文件后产生的字节码文件，不管在win还是linux都可以执行。

执行具体过程：

1. PyCodeObject：PyCodeObject 是 Python 编译器真正编译成的结果。
2. 当 python 程序运行时，编译的结果则是保存在位于内存中的 PyCodeObject 中，当 Python 程序运行结束时，Python 解释器则将 PyCodeObject 写回到 pyc 文件中。
3. 当 python 程序第二次运行时，首先程序会在硬盘中寻找 pyc 文件，如果找到，则直接载入，否则就重复上
面的过程。
4. 每次加载模块时，如果同时存在.py 和.pyc，Python 会尝试使用.pyc，如果.pyc 的编译时间早于.py 的修
改时间，则重新编译.py 并更新.pyc。
5. 所以说 pyc 文件其实是 PyCodeObject 的一种持久化保存方式。
6. PyCodeObject 对象的创建时机是模块加载的时候，即 import。
7. Python 解释器只把我们可能重用到的模块持久化成 pyc 文件，见如下的示例。一般字节码通过反编译都可以很清晰地还原源代码。



查到一个网站（https://tool.lu/pyc/）可以反编译pyc文件。另外工具 uncompyle6 也可以反编译pyc文件



编译完成后就是喜闻乐见的反写代码环节。



经验：了解了.pyc文件的产生缘由，收获 uncompyle6 反编译工具。



## 14.Replace

UPX壳，有工具脱。

看main函数，分析一下。又涉及了固定字符串，点进去dump。

dump到字符串后反写一下，完事。

dump的时候注意IDA相关函数变了：

| 旧的函数        | 新的函数                 | 说明                        |
| --------------- | ------------------------ | --------------------------- |
| **Byte(addr)**  | idc.get_wide_byte(addr)  | 以1字节为单位获取地址处的值 |
| **Word(addr)**  | idc.get_wide_word(addr)  | 同上，以2字节为单位         |
| **Dword(addr)** | idc.get_wide_dword(addr) | 4字节为单位                 |
| **Qword(addr)** | idc.get_qword(addr)      | 8字节为单位                 |



主要难点在于反写时如何处理取余计算，具体参考：https://blog.csdn.net/xiao__1bai/article/details/119986918

另外，IDA查看二进制数组起始以及结束位置有以下格式

byte_402060 db 1A0h dup(0)

简单数组声明，它是一个名为byte_402060的字节数组（db），由416（1A0h）个0值构成。



经验：多写写代码，是好的。



## 15.Reverse

没啥好说的，逆向套餐来一份。

最好用python写，C/C++字符串数学处理一定用unsigned char！因为这里的代码反写涉及了移位操作，有可能会爆数组。



经验：多写写代码吧你！



## 16.testre

逆向套餐。

IDA找main追函数。

有混淆，一句句注释剖析。

重点是数组暴露了加密方式

base58加密数组   123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

base64加密数组   ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

串已经给了，解密就行



经验：加密方式需熟悉，数组+相关操作要看出来。



## 17.Windows_Reverse2

aspack脱壳，吾爱有工具。ESP定律也能脱。

IDA分析

base64加密伪代码：

```
  if ( half_length )
  {
    do
    {
      *(&str + len) = *v4;
      str1_1 = str1;
      ++len;
      --len_half;
      ++v4;
      if ( len == 3 )
      {
        res0 = str >> 2;//这是熟悉的Base64加密算法，而且长度是3的倍数的情况下
        res1 = (str1 >> 4) + 16 * (str & 3);
        res2 = (str2 >> 6) + 4 * (str1 & 0xF);
        res3 = str2 & 0x3F;
        i = 0;
        do
          std::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(//这是C++的字符串运算符重载，把char转成string，方便直接字符叠加在后面。
            &v22,
            (word_1093020[*(&res0 + i++)] ^ 0x76));//从Base64表中（0x1093020）找到十进制下标所在的值异或0x76得到新值存到v22中，一次处理3个字符。
        while ( i < 4 );
        len = 0;
      }
    }
    while ( len_half );
    if ( len )
    {
      if ( len < 3 )//当长度不是3的倍数时，运算完，末尾加“=”填充，算法是一样的。
      {
        memset(&str + len, 0, 3 - len);
        str1_1 = str1;
      }
      res1 = (str1_1 >> 4) + 16 * (str & 3);
      res0 = str >> 2;
      res2 = (str2 >> 6) + 4 * (str1_1 & 0xF);
      k = 0;
```

然后逆向套餐，写解密代码即可。



经验：程序写得还是不够多



## 18.xxxorrr

逆向套餐解决，找加密算法



经验：反调试就IDA，IDA神器



## 19.流浪者

根据密文以及字典，逆向套餐来一份即可。





## 20.梅津美治郎

IDA找字符输入到程序中，过level1

level2可以在IDA内找地址，然后OD下断点得到动态flag



经验：IDA+OD的结合



## 21.shellcode2

一道考察静态分析的题目，要理解如何找到静态分析里的动态载入部分。

一般来说，字符串是直接存好在程序里边的，但是有些程序作者会使用动态载入字符串的方式，让静态分析方法无法获得相关字符串。不过细心查找还是能找出来的。

这一题动态载入函数的方法代码如下：

```
mov     [ebp+var_C0], eax
push    248h            ; Size
push    offset sub_404040 ; Src
mov     ecx, [ebp+var_C0]
push    ecx             ; void *
call    memcpy
add     esp, 0Ch
push    [ebp+var_4]
call    [ebp+var_C0]
```

可以看到，首先程序先把eax的值赋给[ebp+var_C0]，然后push大小进栈，之后push进栈的是sub_404040函数。此时如果用IDA就不能直观的看出该函数与main函数的关系。但我们在这里可以看出函数进栈了。而且在之后也使用了call [ebp+var_C0] 的指令调用函数。这就是动态载入逃过静态分析的一个常用手法。

本题看似是用md5，但实际与md5屁关系没有。最后进入的sub_404040函数通过一步步分析注释，发现代码读取了文件的十六进制作为key，那打开相关软件找找。最后写出解密脚本即可（对，用了异或加密，密钥是16进制数）。

参考：

https://charles.dardaman.com/reverse_engineering/2018/05/26/malwaretech-shellcode-challenge-2.html



## 22.serial-150

文件是ELF64，用IDA。但这题考动态调试。

IDA的动态调试可以参考下方文章。具体就是把 IDA 中 dbgsrc 文件夹里的 linux_service 给拷贝到linux中用chmod执行，然后IDA再接远程debugger即可。

参考：https://blog.csdn.net/abc_670/article/details/80066817

动态调试，下断点追判定语句。7F开头的地址可以不看，因为是系统函数相关的。F8到40开头的地址即可。

这里会遇到一个问题，LOC_004087+1 类型的函数。此类语句 IDA 识别不出来，需要手动用 U 键以及 C 键在函数原本位置对它进行重定义（不是call的那个跳转位置）。

复原这些函数后可以通过修改代码中的数据段达到F5复原函数的作用，但也可以直接通过汇编语句看出flag

https://blog.csdn.net/xiao__1bai/article/details/120197579?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7ECTRLIST%7ERate-1-120197579-blog-105397707.pc_relevant_3mothn_strategy_and_data_recovery&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7ECTRLIST%7ERate-1-120197579-blog-105397707.pc_relevant_3mothn_strategy_and_data_recovery&utm_relevant_index=1



## 23. bad_python

pyc字节码的反编译，但这个pyc是损坏的。

可以自己写一个python程序，然后把正常编译的pyc头接到题目的pyc上边

然后uncompyle6或者在线编译都能复原python代码

通过代码写解密函数即可。





## 24.ey_or

先用 file filename 查看文件类型

然后用 tar -xvf filename 命令解压得到 ey_or 文件，这个 ey_or 就是个 ELF 文件了

用  Linux 里的 strings 命令可以提取到下方字符（用IDA能看到，但只能看到单个字符，而不是像下方成串的）：

```
] ==secret
] ==f
 secret len ==l
 [ ] ==buffer
 0 ==i
 0 ==j
 "Enter Password line by line\n" sys .out .writeall
  #str .fromArray secret bxor
  txt .consume .u
  =j
[ buffer _ len dearray j ] =buffer
[ secret _ len dearray j eq { } { 1 sys .exit } ? * ] =secret
  i 1 add =i 
  i l eq {
  buffer f bxor str .fromArray sys .out .writeall
 0 sys .exit
} { } ? *
} sys .in .eachLine
"ey_or" sys .freeze
```

看WP，说是 Elymas 语言。查文档：https://github.com/Drahflow/Elymas

写成正常语句是：

```
secret = [ ???? ]
f = [ ???? ]
l = len(secret)
buffer = []
i = 0
j = 0
print "Enter Password line by line"
for line in sys.stdin.readlines():
    j = read_int(line)
    buffer = buffer + [j]
    if secret[i] != j:
        sys.exit(1)
    i += 1
    if i == l:
        print to_string(map(lambda x,y: x^y, buffer, f))
        sys.exit(0)
```

解密脚本：

```
import sys
import subprocess

ans = []
while True:
    for j in range(256):
        if j % 16 == 15:
            print(j)
        p = subprocess.Popen("./ey_or.elf", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        for x in ans:
            p.stdin.write(str(x) + '\n')
        p.stdin.write(str(j) + '\n')
        p.stdin.close()
        ret = p.wait()
        if ret != 1:
            ans.append(j)
            print(ans)
            break
```

记得 chmod 777 filename 获取运行权限（找一天看看 chmod 命令）

然后把解密出来的secret用以下脚本输入至ey_or程序内，就能解出flag了。

```
from pwn import *
ans = [36, 30, 156, 30, 43, 6, 116, 22, 211, 66, 151, 89, 36, 82, 254, 81, 182, 134, 24, 90, 119, 6, 88, 137, 64, 197, 251, 15, 116, 220, 161, 94, 154, 252, 139,11, 41, 215, 27, 158, 143, 140, 54, 189, 146, 48, 167, 56, 84, 226, 15, 188, 126,24]p = process('./ey_or')
for x in ans:
p.sendline(str(x))
b = p.recvall()
print(b)
print(p.poll())
p.close()
```

