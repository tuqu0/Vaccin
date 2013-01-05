#include "../include/main.h"

int main (int argc, char **argv) {
	char *dir_name = NULL;

	// init variables
	dir_name = dirname(argv[0]);
	chdir(dir_name);

	printf("isRoot : %d\n", isRoot());
	printf("isSourceHost : %d\n", isSourceHost());

	return 0;
}
