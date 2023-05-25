# Crypto

### 签到题：Binned

给了 enc 和 n 的值，以及密码生成的源码

```
#!/usr/bin/env python3

from Crypto.Util.number import *
from gensafeprime import *
from flag import flag

def keygen(nbit):
	p, q = [generate(nbit) for _ in range(2)]
	return (p, q)

def encrypt(m, pubkey):
	return pow(pubkey + 1, m, pubkey ** 3)

p, q = keygen(512)
n = p * q

flag = bytes_to_long(flag)
enc = encrypt(flag, n)

print(f'pubkey = {n}')
print(f'enc = {enc}')
```

写成数学表达式如下：

![Screenshot_20221015_102745_com.myscript.nebo.huawei](D:\CTF\ASIS2022 CTF\cryptography\binned\binned\Screenshot_20221015_102745_com.myscript.nebo.huawei.jpg)

enc和n都是已知的，未知数是指数flag，用BSGS（baby-step giant-step）算法求。



参考wp的解法：   mod pubkey-------其实这才是正确解法

```
pubkey = 125004899806380680278294077957993138206121343727674199724251084023100054797391533591150992663742497532376954423241741439218367086541339504325939051995057848301514908377941815605487168789148131591458301036686411659334843972203243490288676763861925647147178902977362125434420265824374952540259396010995154324589
 
enc = 789849126571263315208956108629196540107771075292285804732934458641661099043398300667318883764744131397353851782194467024270666326116745519739176492710750437625345677766980300328542459318943175684941281413218985938348407537978884988013947538034827562329111515306723274989323212194585378159386585826998838542734955059450048745917640814983343040930383529332576453845724747105810109832978045135562492851617884175410194781236450629682032219153517122695586503298477875749138129517477339813480115293124316913331705913455692462482942654717828006590051944205639923326375814299624264826939725890226430388059890231323791398412019416647826367964048142887158552454494856771139750458462334678907791079639005383932256589768726730285409763583606927779418528562990619985840033479201147509241313757191997545174262930707521451438204766627975109619779824255444258160
 
# enc = (n+1)^k mod n^3
# enc = (n+1)^k = kn + 1 (mod n^2)  //看懂公式，从后往前看
from Crypto.Util.number import long_to_bytes
 
print(long_to_bytes(enc % pubkey**2 // pubkey))
#ASIS{8!N0miaL_3XpAn5iOn_Us4G3_1N_cRyp7o_9rApHy!}
```

感谢庆华大哥的公式推导思路：

![Screenshot_20221019_154111_com.myscript.nebo.huawei](D:\CTF\ASIS2022 CTF\cryptography\binned\binned\Screenshot_20221019_154111_com.myscript.nebo.huawei.jpg)

参考：http://abloz.com/tech/2018/06/28/solve-exponential/







# WEB

### 签到题：Beginner ducks

打开网页，是一只鸭子的图片。题目给了相关源码，审计源码；

```
#!/usr/bin/env python3
from flask import Flask,request,Response
import random
import re

app = Flask(__name__)
availableDucks = ['duckInABag','duckLookingAtAHacker','duckWithAFreeHugsSign']
indexTemplate = None
flag = None

@app.route('/duck')
def retDuck():
	what = request.args.get('what')
	duckInABag = './images/e146727ce27b9ed172e70d85b2da4736.jpeg'
	duckLookingAtAHacker = './images/591233537c16718427dc3c23429de172.jpeg'
	duckWithAFreeHugsSign = './images/25058ec9ffd96a8bcd4fcb28ef4ca72b.jpeg'

	if(not what or re.search(r'[^A-Za-z\.]',what)):#需要绕过。1、有输入，2、输入为A-Za-z以及.
		return 'what?'
	with open(eval(what),'rb') as f:
		return Response(f.read(), mimetype='image/jpeg')

@app.route("/")
def index():
	return indexTemplate.replace('WHAT',random.choice(availableDucks))#m默认页面，返回鸭子

with open('./index.html') as f:
	indexTemplate = f.read() 
with open('/flag.txt') as f:
	flag = f.read()

if(__name__ == '__main__'):
	app.run(port=8000)
	
```

很显然，这题考正则绕过。然后这个正则过滤的东西在下边：

![屏幕截图 2022-10-15 114153](D:\CTF\ASIS2022 CTF\web\beginner ducks\beginner-duck_e07a773303522f0ef1b15cc345cf2c9885132daf\beginner-duck\屏幕截图 2022-10-15 114153.jpg)

而且以及明说了，flag就要输入/flag.txt，然而 / 被过滤了。查查绕过方式。

但很可惜，其实不用绕过的。只需要让 what=f.name 就能达到 /flag.txt 输入的效果

f.name  显示文件路径。如果是通过相对路径打开的文件，则显示  ././a.txt

绝对路径则返回  D:/test/project/a.txt  

参考：http://www.ctfiot.com/63407.html