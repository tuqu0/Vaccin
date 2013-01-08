#ifndef UTILS_H
#define UTILS_H

 #include "dictionary.h"
 #include "iniparser.h" 
 #include <syslog.h>
 #include <stdlib.h>
 #include <stdbool.h>

 #define CONFIG_FILE "config.ini"
 #define SYSLOG_PROGRAM "vaccin"

 /*
 * Write a message in syslog.
 */
 void syslogMsg(char *msg);

 /*
 * Read and check the configuration file
 */
 dictionary* GetConfig();

#endif /* UTILS_H */
