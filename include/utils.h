#ifndef UTILS_H
#define UTILS_H

 #include "dictionary.h"
 #include "iniparser.h" 
 #include <syslog.h>
 #include <stdlib.h>
 #include <stdbool.h>
 #include <string.h>

 #define CONFIG_FILE "config.ini"
  
 /*
 *  Parameters of the configuration file
 */
 extern dictionary *params;

 /*
 *  Read and check the configuration file
 */
 void readConfig();

 /*
 * Write a message in syslog
 */
 void syslogMsg(char *msg);

 /*
 * Replace a substring by another
 */
 char* str_replace(char *str, char *sub_str, char *replacement);

#endif /* UTILS_H */
