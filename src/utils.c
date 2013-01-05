#include "../include/utils.h"

void writeSyslog(char *msg) {
	openlog(WORM_NAME, LOG_PID, LOG_USER);
	syslog(LOG_NOTICE, msg);
	closelog();
}

char* GetConfigServer() {
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
				if (strstr(line, "server=") != NULL) {
					token = strtok(line, "=");
					token = strtok(NULL, "\r\n");
					if (token != NULL && strlen(token) > 1) {
						server = (char *) malloc(strlen(token) + 1);
						if (server != NULL)
							strcpy(server, token);
						break;
					}
				}
			}
			fclose(fd);
		}
	}
	return server;
}

char* GetConfigControl() {
	size_t len = 0;
	ssize_t read;
	FILE *fd = NULL;
	char *line = NULL;
	char *token = NULL;
	char *control = NULL;

	if (access(CONFIG_FILE, R_OK) == 0) {
		fd = fopen(CONFIG_FILE, "r");
		if (fd != NULL) {
			while ((read = getline(&line, &len, fd)) != -1) {
				if (strstr(line, "control=") != NULL) {
					token = strtok(line, "=");
					token = strtok(NULL, "\r\n");
					if (token != NULL && strlen(token) > 1) {
						control = (char *) malloc(strlen(token) + 1);
						if (control != NULL)
							strcpy(control, token);
						break;
					}
				}
			}
			fclose(fd);
		}
	}
	return control;
}

char* GetConfigCommand() {
	size_t len = 0;
	ssize_t read;
	FILE *fd = NULL;
	char *line = NULL;
	char *token = NULL;
	char *command = NULL;

	if (access(CONFIG_FILE, R_OK) == 0) {
		fd = fopen(CONFIG_FILE, "r");
		if (fd != NULL) {
			while ((read = getline(&line, &len, fd)) != -1) {
				if (strstr(line, "command=") != NULL) {
					token = strtok(line, "=");
					token = strtok(NULL, "\r\n");
					if (token != NULL && strlen(token) > 1) {
						command = (char *) malloc(strlen(token) + 1);
						if (command != NULL)
							strcpy(command, token);
						break;
					}
				}
			}
			fclose(fd);
		}
	}
	return command;
}
