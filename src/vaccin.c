#include "../include/vaccin.h"

int isRoot() {
	int ret = 0;

	if (getuid() == 0 && geteuid() == 0) {
		writeSyslog("## Launching vaccin by root.");
		ret = 1;
	}
	return ret;
}

int isSourceHost(char *source_host_ip, char *mask_network) {
	int ret = 0;
	char buf[IP_LEN];
	char *server = NULL;
	struct ifaddrs *myaddrs = NULL;
	struct ifaddrs *ifa = NULL;
	struct sockaddr_in *s4 = NULL;
	struct sockaddr_in *mask = NULL;

	ret = getifaddrs(&myaddrs);
	if (ret != 0)
		return ret;
	server = GetConfigServer();
	if (server == NULL)
		return ret;

	ret = 1;
	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET) {
			s4 = (struct sockaddr_in *) (ifa->ifa_addr);
			if (inet_ntop(ifa->ifa_addr->sa_family, (void *) &(s4->sin_addr), buf, sizeof(buf)) != NULL) {
				if (!strcmp(server, buf)) {
					memset(source_host_ip, 0, IP_LEN);
					strcpy(source_host_ip, buf);
					memset(buf, 0, sizeof(buf));
					mask = (struct sockaddr_in *) (ifa->ifa_netmask);
					inet_ntop(ifa->ifa_netmask->sa_family, (void *) &(mask->sin_addr), buf, sizeof(buf));
					memset(mask_network, 0, IP_LEN);
					strcpy(mask_network, buf);
					writeSyslog("## We are the administrator's host.");
					ret = 1;
					break;
				}
				memset(buf, 0, sizeof(buf));
				ret = 0;
			}
		}
	}
	free(myaddrs);	
	return ret;
}

struct in_addr* scanNetwork(char* source_host_ip, char* mask_network) {
	struct sockaddr_in sockHostIP;
	unsigned long int nbrComputer, hostMask, i;
	int sock, compteur = 0;
	char nbrComputer_[80];
	struct in_addr mask, broadcast, hostIP, sourceIP, *resultIP = NULL;
	char *msg = NULL;

	writeSyslog("## Launching network scan.");
	inet_aton(source_host_ip, &sourceIP);
	inet_aton(mask_network, &mask);
	inet_aton(BROADCAST, &broadcast);
	nbrComputer = ntohl(broadcast.s_addr ^ mask.s_addr);
	hostMask = sourceIP.s_addr & mask.s_addr;

	sprintf(nbrComputer_, "%lu", nbrComputer);
	msg = (char *) malloc(strlen("## Maximal number of hosts on this network : ") + strlen(nbrComputer_) + 1);
	if (msg != NULL) {
		strcpy(msg, "## Maximal number of hosts on this network : ");
		strcat(msg, nbrComputer_);
		writeSyslog(msg);
		free(msg);
	}

	for (i = 1; i < nbrComputer; i++) {
		hostIP.s_addr = htonl(ntohl(hostMask) + i);
		if (strcmp(inet_ntoa(hostIP), source_host_ip) == 0) {
			msg = (char *) malloc(strlen("## Host administrator found : ") + strlen(source_host_ip));
			if (msg != NULL) {
				strcpy(msg, "## Host administrator found : ");
				strcat(msg, source_host_ip);
				writeSyslog(msg);
				free(msg);
			}
			continue;
		}

		bzero(&sockHostIP, sizeof(sockHostIP));
		sock = socket(AF_INET, SOCK_STREAM, 0);
		sockHostIP.sin_family = AF_INET;
		sockHostIP.sin_port = htons(PORT);
		sockHostIP.sin_addr = hostIP;
		if (connect(sock, (struct sockaddr *) & sockHostIP, sizeof(sockHostIP)) == 0) {
			resultIP = (struct in_addr *) realloc(resultIP, (compteur + 1) * sizeof(struct in_addr));
			resultIP[compteur] = hostIP;
			compteur++;
			msg = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + strlen(" tested and ssh port is open") + 4);
			if (msg != NULL) {
				strcpy(msg, "## ");
				strcat(msg, inet_ntoa(sockHostIP.sin_addr));
				strcat(msg, " tested and ssh port is open");
				writeSyslog(msg);
				free(msg);
			}
		}
		else {
			msg = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + strlen(" tested") + 4);
			if (msg != NULL) {
				strcpy(msg, "## ");
				strcat(msg, inet_ntoa(sockHostIP.sin_addr));
				strcat(msg, " tested");
				writeSyslog(msg);
				free(msg);
			}
			continue;
		}
	}
	return resultIP;
}

int isAlreadyColonize(char *host, char *program) {
	int ret = 0;
	char command[4096];
	char *program_path = NULL;

	program_path = (char *) malloc(strlen(program) + strlen(CLIENT_PATH) + 1);
	if (program_path == NULL)
		return ret;

	strcpy(program_path, CLIENT_PATH);
	strcat(program_path, program);
	sprintf(command, "%s -p %d %s \"test -f %s\"", SSH, PORT, host, program_path);
	free(program_path);

	ret = system(command);
	if (ret == 0)
		return 1;
	return 0;
}

int colonize(char *host, char *file) {
	int ret = 0;
	char command[4096];
	char *msg = NULL;
	char *dir = NULL;
	char *config = NULL;

	if (access(SCP, R_OK) != 0 || access(SSH, R_OK) != 0)
		return ret;

	dir = (char *) malloc(strlen(file));
	if (dir == NULL)
		return ret;
	strcpy(dir, file);
	dirname(dir);

	config = (char *) malloc(strlen(dir) + strlen(CONFIG_FILE) + 2);
	if (config == NULL)
		return ret;
	strcpy(config, dir);
	strcat(config, "/");
	strcat(config, CONFIG_FILE);

	if (access(file, R_OK) != 0 || access(config, R_OK) != 0) {
		free(dir);
		free(config);
		return ret;
	}

	msg = (char *) malloc(strlen("## colonization of ") + strlen(host));
	if (msg != NULL) {
		strcpy(msg, "## colonization of ");
		strcat(msg, host);
		writeSyslog(msg);
		free(msg);
	}

	sprintf(command, "%s -P %d %s root@%s:%s", SCP, PORT, file, host, CLIENT_PATH);
	ret = system(command);
	if (ret != 0) {
		free(dir);
		free(config);
		return 0;
	}
	memset(command, 0, 4096);

	sprintf(command, "%s -P %d %s root@%s:%s", SCP, PORT, config, host, CLIENT_PATH);
	ret = system(command);
	if (ret != 0) {
		free(dir);
		free(config);
		return 0;
	}

	return 1;
}
