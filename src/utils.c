#include "../include/utils.h"

int isRoot() {
	int ret = 1;

	if (getuid() == 0 && geteuid() == 0)
		ret = 0;

	return ret;
}

int isSourceHost() {
	int ret = 1;
	char buf[64];
	char *server_ip = NULL;
	struct ifaddrs *myaddrs = NULL;
	struct ifaddrs *ifa = NULL;
	struct sockaddr_in *s4 = NULL;

	if ((ret = getifaddrs(&myaddrs)) != 0)
		return ret;
	
	if ((server_ip = LoadServerIPAddress()) == NULL)
		return 1;

	ret = 1;
	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET) {
			s4 = (struct sockaddr_in *) (ifa->ifa_addr);

			if (inet_ntop(ifa->ifa_addr->sa_family, (void *) &(s4->sin_addr), buf, sizeof(buf)) != NULL) {
				if (!strcmp(server_ip, buf))
					ret = 0;
				memset(buf, 0, sizeof(buf));
			}
		}
	}

	free(myaddrs);	

	return ret;
}

char* LoadServerIPAddress() {
	FILE *fd = NULL;
	size_t len = 0;
	ssize_t read;
	char *line = NULL;
	char *token = NULL;
	char *server_ip = NULL;

	if (access(CONFIG_FILE, R_OK) == 0) {
		fd = fopen(CONFIG_FILE, "r");

		if (fd != NULL) {
			while ((read = getline(&line, &len, fd)) != -1) {
				token = strtok(line, "server_ip=");
				token = strtok(token, "\n");
			
				if (token != NULL && strlen(token) > 1) {
					server_ip = (char *) malloc(strlen(token) + 1);
			
					if (server_ip != NULL)
						strcpy(server_ip, token);
					break;
				}
			}
			fclose(fd);
		}
	}

	return server_ip;
}
