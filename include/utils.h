#ifndef UTILS_H
 #define UTILS_H

 #include "dictionary.h"
 #include "iniparser.h" 
 #include <syslog.h>
 #include <stdlib.h>
 #include <stdbool.h>

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

#endif /* UTILS_H */
