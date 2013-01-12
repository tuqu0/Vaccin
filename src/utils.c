#include "../include/utils.h"

void readConfig()
{
	int ssh_port = -1;
	char *ip_admin, *command, *control, *target_dir, *crontab;
	char *scp_path, *ssh_path, *broadcast, *output, *schedule;

	// load the configuration file	
	params = iniparser_load(CONFIG_FILE);
	if (params == NULL)
		exit(EXIT_FAILURE);
	
	// get parameters
	ip_admin = iniparser_getstring(params, "Administrator:ip", NULL);
	command = iniparser_getstring(params, \
				      "Administrator:command", NULL);
	output = iniparser_getstring(params, "Administrator:output", NULL);
	control = iniparser_getstring(params, "Target:control", NULL);
	target_dir = iniparser_getstring(params, "Target:targetPath", NULL);
	crontab = iniparser_getstring(params, "Target:crontab", NULL);
	schedule = iniparser_getstring(params, "Target:schedule", NULL);
	scp_path = iniparser_getstring(params, "Network:scp", NULL);
	ssh_path = iniparser_getstring(params, "Network:ssh", NULL);
	ssh_port = iniparser_getint(params, "Network:portSSH", -1);
	broadcast = iniparser_getstring(params, "Network:broadcast", NULL);

	if (ip_admin == NULL || command == NULL || control == NULL || \
	    target_dir == NULL || crontab == NULL || scp_path == NULL || \
	    ssh_path == NULL || ssh_port == -1 || broadcast == NULL || \
	    output == NULL || schedule == NULL) {
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

char* str_replace(char *str, char *sub_str, char *replacement)
{
	char *token, *new_str, *old_str, *head;

	new_str = strdup(str);
	head = new_str;
	while ((token = strstr(head, sub_str))) {
		old_str = new_str;
		new_str = malloc(strlen(old_str) - strlen(sub_str) + strlen(replacement) + 1);
		if (new_str == NULL) {
			free(old_str);
			return NULL;
		}
		memcpy(new_str, old_str, token - old_str);
		memcpy(new_str + (token - old_str), replacement, strlen(replacement));
		memcpy(new_str + (token - old_str) + strlen(replacement), token + strlen(sub_str), \
			strlen(old_str) - strlen(sub_str) - (token - old_str));
		memset(new_str + strlen(old_str) - strlen(sub_str) + strlen(replacement), 0, 1);
		head = new_str + (token - old_str) + strlen(replacement);
		free(old_str);
	}

	return new_str;
}
