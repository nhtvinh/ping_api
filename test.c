#include <stdio.h>

#include "ping.h"

int
main(int argc, char **argv)
{
	int status = 0;

	if (argc > 1)
		status = ping4_api(argv[argc-1]);
	
	printf("status:%d\n", status);

	return status; 
}
