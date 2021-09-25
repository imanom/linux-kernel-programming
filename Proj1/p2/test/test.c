#include <stdio.h>
#include <stdlib.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char* argv)
{
	int opt;
	int key;
	char* msg;
	while((opt=getopt(argc, argv, ":s:k:")) != -1)
	{
		switch(opt)
		{
			case 's':
				printf("msg: %s\n", optarg);
				msg = optarg;
				break;
			case 'k':
				printf("key: %s\n", optarg);
				key = atoi(optarg);
				break;
			case '?':
				printf("unknown option\n");
				break;
		}
	}
	//syscall number 447 is the newly created syscall for encrypt.
	int num = syscall(447, msg, key);
	printf("Returned val = %d\n",num);
	return 0;
}
