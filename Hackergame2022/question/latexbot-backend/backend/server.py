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
