不确定文件类型时，从文件头看文件类型。注意，有时候拿到的直接是ASCII码形式的，也要看出这是某类型的文件。如ZIP开头是PK（50 4B）

![文件类型图片](D:\CTF\文件类型图片.png)

文件尾部再次确认文件类型

zip：504B0506

rar：C43D7B00400700

jpg/jpeg：FFD9

png：000049454E44AE426082

gif：3B





A文件中包含B文件情况->使用文件分离

工具：Binwalk 、foremost  平台：linux

