#ifndef UTILS_H
#define UTILS_H
 
 #include <syslog.h>
 #include <unistd.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>

 #define WORM_NAME "vaccin"
 #define CONFIG_FILE "config.ini"

 /*
 * Write a message in syslog
 */
 void writeSyslog(char *msg);

 /*
 * Get the server ip address from the configuration file
 */
 char* GetConfigServer();

 /*
 * Get the control fille from the configuration file
 */
 char* GetConfigControl();

 /*
 * Get the command file from the configuration file
 */
 char* GetConfigCommand();

#endif /* UTILS_H */
