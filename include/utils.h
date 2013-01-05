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
 #define BROADCAST "255.255.255.255"
 #define PORT 22
 #define IP_LEN 16

 /*
 * Check if the program is launched by root
 */
 int isRoot();

 /*
 * Check if a network interface on the system is configured with the "server_ip" address
 * defined in the configuration file.
 */
 int isSourceHost(char* source_host_ip, char* mask_network);

 /*
 * Get the server ip address from the configuration file
 */
 char* LoadServerIPAddress();

 /*
 * Scan subnetwork defined by the source_host_ip and the mask_network
 */
 struct in_addr* scanNetwork(char* source_host_ip, char* mask_network);

#endif /* UTILS_H */
