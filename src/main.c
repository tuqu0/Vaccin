#include "../include/main.h"

int main (int argc, char **argv) {
	char *dir_name = NULL;
	char *source_host_ip = NULL;
	char *mask_network = NULL;
	struct in_addr *hostList = NULL;
	struct in_addr srcHost;
	int i = 0;

	// init variables
	dir_name = dirname(argv[0]);
	chdir(dir_name);

	if (isRoot()) {
		source_host_ip = (char *) malloc(sizeof(char) * IP_LEN);
		mask_network = (char *) malloc(sizeof(char) * IP_LEN);

		if (source_host_ip == NULL || mask_network == NULL)
			return EXIT_FAILURE;

		if(isSourceHost(source_host_ip, mask_network)) {
			hostList = scanNetwork(source_host_ip, mask_network);
			inet_aton(source_host_ip, &srcHost);

			while (1) {
				if (inet_netof(hostList[i]) == inet_netof(srcHost)) {
					continue;
				}
			}
		}

		free(source_host_ip);
		free(mask_network);
	}

	return EXIT_SUCCESS;
}
