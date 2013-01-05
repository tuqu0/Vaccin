#ifndef UTILS_H
#define UTILS_H

 #include <unistd.h>
 #include <sys/types.h>
 #include <ifaddrs.h>
 #include <arpa/inet.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>

 #define CONFIG_FILE "config.ini"

 /*
 * Check if the program is launched by root
 */
 int isRoot();

 /*
 * Check if a network interface on the system is configured with the "server_ip" address
 * defined in the configuration file.
 */
 int isSourceHost();

 /*
 * Get the server ip address from the configuration file
 */
 char* LoadServerIPAddress();

#endif /* UTILS_H */
