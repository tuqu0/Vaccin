#ifndef VACCIN_H
#define VACCIN_H

 #include "utils.h"
 #include <unistd.h>
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <sys/types.h>
 #include <ifaddrs.h>
 #include <arpa/inet.h>
 
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
 * Scan subnetwork defined by the source_host_ip and the mask_network
 */
 struct in_addr* scanNetwork(char* source_host_ip, char* mask_network);

#endif /* VACCCIN_H */
