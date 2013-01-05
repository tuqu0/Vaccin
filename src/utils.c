#include "../include/utils.h"

void writeSyslog(char *msg) {
	openlog(WORM_NAME, LOG_PID | LOG_CONS, LOG_USER);
	syslog(LOG_INFO, msg);
	closelog();
}

int isRoot() {
	int ret = 0;

	if (getuid() == 0 && geteuid() == 0) {
		writeSyslog("## Launching vaccine by root.");
		ret = 1;
	}
	return ret;
}

char* LoadServerIPAddress() {
	size_t len = 0;
	ssize_t read;
	FILE *fd = NULL;
	char *line = NULL;
	char *token = NULL;
	char *server = NULL;

	if (access(CONFIG_FILE, R_OK) == 0) {
		fd = fopen(CONFIG_FILE, "r");

		if (fd != NULL) {
			while ((read = getline(&line, &len, fd)) != -1) {
				token = strtok(line, "server=");
				token = strtok(token, "\n");

				if (token != NULL && strlen(token) > 1) {
					server = (char *) malloc(strlen(token) + 1);

					if (server != NULL)
						strcpy(server, token);
					break;
				}
			}
			fclose(fd);
		}
	}
	return server;
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

	server = LoadServerIPAddress();
	if (server == NULL)
		return ret;

	ret = 0;
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
			}
		}
	}
	free(myaddrs);	
	return ret;
}

struct in_addr* scanNetwork(char* source_host_ip, char* mask_network) {
	struct in_addr mask, broadcast, hostIP, sourceIP, *resultIP = NULL;
	struct sockaddr_in sockHostIP;
	unsigned long int nbrComputer, hostMask, i;
	int sock, compteur = 0;
	char nbrComputer_[80];
	char *syslog_ = NULL;

	writeSyslog("## Launching network scan.");
	inet_aton(source_host_ip, &sourceIP);
	inet_aton(mask_network, &mask);
	inet_aton(BROADCAST, &broadcast);
	nbrComputer = ntohl(broadcast.s_addr ^ mask.s_addr);
	hostMask = sourceIP.s_addr & mask.s_addr;
	
	sprintf(nbrComputer_, "%lu", nbrComputer);
	syslog_ = (char *) malloc(strlen("## Maximal number of hosts on this network : ") + strlen(nbrComputer_) + 1);
	if (syslog_ != NULL) {
		strcpy(syslog_, "## Maximal number of hosts on this network : ");
		strcat(syslog_, nbrComputer_);
		writeSyslog(syslog_);
		free(syslog_);
	}

	for (i = 1; i < nbrComputer; i++) {
		hostIP.s_addr = htonl(ntohl(hostMask) + i);

		if (strcmp(inet_ntoa(hostIP), source_host_ip) == 0) {
			syslog_ = (char *) malloc(strlen(source_host_ip) + strlen("## Host administrator found : "));
			if (syslog_ != NULL) {
				strcpy(syslog_, "## Host administrator found : ");
				strcat(syslog_, source_host_ip);
				writeSyslog(syslog_);
				free(syslog_);
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
			syslog_ = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + strlen(" tested and ssh port is open") + 4);
			if (syslog_ != NULL) {
				strcpy(syslog_, "## ");
				strcat(syslog_, inet_ntoa(sockHostIP.sin_addr));
				strcat(syslog_, " tested and ssh port is open");
				writeSyslog(syslog_);
				free(syslog_);
			}
		}
		else {
			syslog_ = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + strlen(" tested") + 4);
			if (syslog_ != NULL) {
				strcpy(syslog_, "## ");
				strcat(syslog_, inet_ntoa(sockHostIP.sin_addr));
				strcat(syslog_, " tested");
				writeSyslog(syslog_);
				free(syslog_);
			}
			continue;
		}
	}

	return resultIP;
}
