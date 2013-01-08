#include "../include/utils.h"

void readConfig()
{
	int ssh_port = -1;
	char *ip_admin, *command, *control, *target_dir, *crontab;
	char *scp_path, *ssh_path, *broadcast;

	// load the configuration file	
	params = iniparser_load(CONFIG_FILE);
	if (params == NULL)
		exit(EXIT_FAILURE);
	
	// get parameters
	ip_admin = iniparser_getstring(params, "Administrator:ip", NULL);
	command = iniparser_getstring(params, \
				      "Administrator:command", NULL);
	control = iniparser_getstring(params, "Target:control", NULL);
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);
	crontab = iniparser_getstring(params, "Target:crontab", NULL);
	scp_path = iniparser_getstring(params, "Network:scp", NULL);
	ssh_path = iniparser_getstring(params, "Network:ssh", NULL);
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);
	broadcast = iniparser_getstring(params, "Network:broadcast", NULL);

	if (ip_admin == NULL || command == NULL || control == NULL || \
	    target_dir == NULL || crontab == NULL || scp_path == NULL || \
	    ssh_path == NULL || ssh_port == -1 || broadcast == NULL) {
		iniparser_freedict(params);
		exit(EXIT_FAILURE);
	}
}

void syslogMsg(char *msg)
{
	openlog("vaccin", LOG_PID, LOG_USER);
	syslog(LOG_NOTICE, msg);
	closelog();
}
