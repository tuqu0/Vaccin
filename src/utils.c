#include "../include/utils.h"

void syslogMsg(char *msg)
{
	// write a message in syslog
	openlog(SYSLOG_PROGRAM, LOG_PID, LOG_USER);
	syslog(LOG_NOTICE, msg);
	closelog();
}

dictionary* GetConfig()
{
	int portSSH = -1;
	char *ip , *command, *control, *targetPath, *crontab, *scp, *ssh, *broadcast;
	dictionary *dico;

	// load the configuration file
	dico = iniparser_load(CONFIG_FILE);
	
	// get parameters
	ip = iniparser_getstring(dico, "Administrator:ip", NULL);
	command = iniparser_getstring(dico, "Administrator:command", NULL);
	control = iniparser_getstring(dico, "Target:control", NULL);
	targetPath = iniparser_getstring(dico, "Target:targetPath", NULL);
	crontab = iniparser_getstring(dico, "Target:crontab", NULL);
	scp = iniparser_getstring(dico, "Network:scp", NULL);
	ssh = iniparser_getstring(dico, "Network:ssh", NULL);
	portSSH = iniparser_getint(dico, "Network:portSSH", -1);
	broadcast = iniparser_getstring(dico, "Network:broadcast", NULL);

	if (ip != NULL && command != NULL && control != NULL && targetPath != NULL && crontab != NULL && scp != NULL && ssh != NULL && portSSH != -1 && broadcast != NULL) {
		return dico;
	}
	else {
		exit(EXIT_FAILURE);
	}
}
