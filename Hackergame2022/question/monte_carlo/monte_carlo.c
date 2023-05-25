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

	srand((unsigned)time(0) + clock());
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
	if (win >= 3) {
		printf("胜利！\n");
	}
	else printf("胜败乃兵家常事，大侠请重新来过吧！\n");
	return 0;
}
