#!/usr/bin/env python
# coding=utf-8
#############################################
#
# French string catalog for SET (see src/core/i18n.py).
#
# Keyed by the exact English string used in the source, same convention as
# gettext .po files: CATALOG["English source string"] = "Traduction".
#
# Keep keys byte-for-byte identical to the English literal they replace
# (including punctuation and trailing spaces) or the lookup silently misses
# and the English text is shown instead.
#
#############################################

CATALOG = {
    # src/core/update_config.py
    "New set.config.py file generated on: %s": "Nouveau fichier set.config.py généré le : %s",
    "Verifying configuration update...": "Vérification de la mise à jour de la configuration...",
    "Update verified, config timestamp is: %s": "Mise à jour vérifiée, l'horodatage de la config est : %s",
    "Update failed? Timestamp on config file is: %s": "Mise à jour échouée ? L'horodatage du fichier de config est : %s",
    "SET is using the new config, no need to restart": "SET utilise la nouvelle configuration, pas besoin de redémarrer",

    # src/core/module_handler.py
    "Social-Engineer Toolkit Third Party Modules menu.": "Menu des modules tiers du Social-Engineer Toolkit.",
    "Please read the readme/modules.txt for information on how to create your own modules.\n": "Veuillez lire readme/modules.txt pour savoir comment créer vos propres modules.\n",
    "\n  99. Return to the previous menu\n": "\n  99. Retour au menu précédent\n",
    "An integer was not used try again": "Vous n'avez pas saisi un nombre entier, réessayez",
    "   [!] There was an issue with a module: %s.": "   [!] Un problème est survenu avec un module : %s.",

    # src/core/payloadgen/solo.py
    "Payload has been exported to the default SET directory located under: ": "Le payload a été exporté vers le dossier par défaut de SET situé sous : ",
    "IP address for the payload listener (LHOST)": "Adresse IP pour le listener du payload (LHOST)",
    "Enter the PORT for the reverse listener": "Entrez le PORT pour le listener inversé",
    "Generating the payload.. please be patient.": "Génération du payload.. merci de patienter.",
    "Do you want to start the payload and listener now? (yes/no)": "Voulez-vous démarrer le payload et le listener maintenant ? (yes/no)",
    "Launching msfconsole, this could take a few to load. Be patient...": "Lancement de msfconsole, le chargement peut prendre un moment. Soyez patient...",

    # src/core/arp_cache/arp.py
    "ARP Cache Poisoning is set to ": "L'empoisonnement du cache ARP est réglé sur ",
    "DSNIFF DNS Poisoning is set to ": "L'empoisonnement DNS DSNIFF est réglé sur ",
    "IP address to connect back on: ": "Adresse IP pour la connexion retour : ",
    """
  This attack will poison all victims on your local subnet, and redirect them
  when they hit a specific website. The next prompt will ask you which site you
  will want to trigger the DNS redirect on. A simple example of this is if you
  wanted to trigger everyone on your subnet to connect to you when they go to
  browse to www.google.com, the victim would then be redirected to your malicious
  site. You can alternatively poison everyone and everysite by using the wildcard
  '*' flag.

  IF YOU WANT TO POISON ALL DNS ENTRIES (DEFAULT) JUST HIT ENTER OR *
""": """
  Cette attaque va empoisonner toutes les victimes de votre sous-réseau local et les
  rediriger lorsqu'elles accèdent à un site spécifique. La prochaine invite vous demandera
  quel site doit déclencher la redirection DNS. Un exemple simple : si vous voulez que
  tout le monde sur votre sous-réseau soit redirigé vers vous lorsqu'il navigue vers
  www.google.com, la victime sera alors redirigée vers votre site malveillant. Vous
  pouvez aussi empoisonner tout le monde et tous les sites avec le joker '*'.

  SI VOUS VOULEZ EMPOISONNER TOUTES LES ENTRÉES DNS (PAR DÉFAUT), APPUYEZ SIMPLEMENT SUR ENTRÉE OU *
""",
    "Example: http://www.google.com": "Exemple : http://www.google.com",
    "Site to redirect to attack machine [*]": "Site à rediriger vers la machine attaquante [*]",
    "LAUNCHING ETTERCAP DNS_SPOOF ATTACK!": "LANCEMENT DE L'ATTAQUE DNS_SPOOF ETTERCAP !",
    "ERROR:An error has occured:": "ERREUR : une erreur est survenue :",
    "ERROR:": "ERREUR :",
    "LAUNCHING DNSSPOOF DNS_SPOOF ATTACK!": "LANCEMENT DE L'ATTAQUE DNS_SPOOF DNSSPOOF !",
    "Press <return> to begin dsniff.": "Appuyez sur <entrée> pour démarrer dsniff.",
    "ERROR:An error has occurred:": "ERREUR : une erreur est survenue :",
    "ERROR": "ERREUR",

    # src/fasttrack/sccm/sccm_main.py
    "The": "Le",
    " SCCM Attack Vector ": " vecteur d'attaque SCCM ",
    "will utilize the SCCM configurations to deploy malicious software. \n\n"
    "You need to have the SMSServer name and a PackageID you want to package "
    "on the website. Then you need to copy this configuration file to the "
    "startup directory for all of the users on the server.":
        "va utiliser les configurations SCCM pour déployer un logiciel malveillant. \n\n"
        "Vous devez disposer du nom du serveur SMS et de l'ID du package à empaqueter "
        "sur le site. Vous devez ensuite copier ce fichier de configuration dans le "
        "dossier de démarrage pour tous les utilisateurs du serveur.",
    "Enter the IP address or hostname of the SMS Server: ": "Entrez l'adresse IP ou le nom d'hôte du serveur SMS : ",
    "Enter the Package ID of the package you want to patch: ": "Entrez l'ID du package que vous voulez patcher : ",
    "The SCCM configuration script has been successfully created.": "Le script de configuration SCCM a été créé avec succès.",
    "You need to copy the script to the startup folder of the server.": "Vous devez copier le script dans le dossier de démarrage du serveur.",
    "Report has been exported to {0}": "Le rapport a été exporté vers {0}",
    "Press ": "Appuyez sur ",
    "{return} ": "{entrée} ",
    "to exit this menu.": "pour quitter ce menu.",

    # src/fasttrack/psexec.py
    "Enter the IP Address or range (RHOSTS) to connect to": "Entrez l'adresse IP ou la plage (RHOSTS) à laquelle se connecter",
    "Enter the username": "Entrez le nom d'utilisateur",
    "Enter the password or the hash": "Entrez le mot de passe ou le hash",
    "Enter the domain name (hit enter for logon locally)": "Entrez le nom de domaine (entrée pour une connexion locale)",
    "How many threads do you want [enter for default]": "Combien de threads voulez-vous [entrée pour la valeur par défaut]",
    "Enter the port for the reverse [443]": "Entrez le port pour le reverse [443]",
    "Prepping the payload for delivery and injecting alphanumeric shellcode...": "Préparation du payload pour la livraison et injection du shellcode alphanumérique...",
    "If you want the powershell commands and attack, they are exported to {0}": "Si vous voulez les commandes PowerShell et l'attaque, elles sont exportées vers {0}",
    "Launching Metasploit.. This may take a few seconds.": "Lancement de Metasploit.. Cela peut prendre quelques secondes.",
    "Something went wrong printing error: {0}": "Quelque chose s'est mal passé, affichage de l'erreur : {0}",

    # src/fasttrack/autopwn.py
    "Prepping the answer file based on what was specified.": "Préparation du fichier de réponses en fonction de ce qui a été spécifié.",
    "Using the {0} sql driver for autopwn": "Utilisation du driver SQL {0} pour autopwn",
    "Autopwn will attack the following systems: {0}": "Autopwn va attaquer les systèmes suivants : {0}",
    "Answer file has been created and prepped for delivery into Metasploit.\n": "Le fichier de réponses a été créé et préparé pour être transmis à Metasploit.\n",
    "Launching Metasploit and attacking the systems specified. This may take a moment..": "Lancement de Metasploit et attaque des systèmes spécifiés. Cela peut prendre un moment..",
    "Doing do_autopwn": "Exécution de do_autopwn",
    "Enter the IP ranges to attack (nmap syntax only)": "Entrez les plages IP à attaquer (syntaxe nmap uniquement)",
    "You are about to attack systems are you sure [y/n]": "Vous êtes sur le point d'attaquer des systèmes, êtes-vous sûr [y/n]",

    # src/fasttrack/exploits/f5.py
    """
    Title: F5 BIG-IP Remote Root Authentication Bypass Vulnerability (py)

    Quick script written by Dave Kennedy (ReL1K) for F5 authentication root bypass
    http://www.trustedsec.com
    """: """
    Titre : Vulnérabilité de contournement d'authentification root distant F5 BIG-IP (py)

    Script rapide écrit par Dave Kennedy (ReL1K) pour le contournement d'authentification root F5
    http://www.trustedsec.com
    """,
    "Enter the IP address of the F5: ": "Entrez l'adresse IP du F5 : ",

    # src/fasttrack/exploits/ms08067.py
    "Enter your LHOST (attacker IP address) for the reverse listener: ": "Entrez votre LHOST (adresse IP de l'attaquant) pour le listener inversé : ",
    "Enter your LPORT (attacker port) for the reverse listener: ": "Entrez votre LPORT (port de l'attaquant) pour le listener inversé : ",
    "Enter the RHOST (victim IP) for MS08-067: ": "Entrez le RHOST (IP de la victime) pour MS08-067 : ",
    "Enter your payload (example: windows/meterpreter/reverse_https) - just hit enter for reverse_https: ": "Entrez votre payload (exemple : windows/meterpreter/reverse_https) - appuyez simplement sur entrée pour reverse_https : ",

    # src/fasttrack/exploits/mysql_bypass.py
    """
This has to be the easiest "exploit" ever. Seriously. Embarassed to submit this a little.

Title: MySQL Remote Root Authentication Bypass
Written by: Dave Kennedy (ReL1K)
http://www.trustedsec.com

Original advisory here: seclists.org/oss-sec/2012/q2/493

Note, you will see a number of failed login attempts, after about 300, if it doesn't
work, then its not vulnerable.
""": """
C'est sûrement l'"exploit" le plus simple qui existe. Sérieusement. Un peu gênant de le soumettre.

Titre : Contournement d'authentification root distant MySQL
Écrit par : Dave Kennedy (ReL1K)
http://www.trustedsec.com

Avis d'origine ici : seclists.org/oss-sec/2012/q2/493

Notez que vous verrez un certain nombre de tentatives de connexion échouées ; après environ 300,
si ça ne fonctionne pas, c'est que la cible n'est pas vulnérable.
""",
    "Enter the IP address of the mysql server: ": "Entrez l'adresse IP du serveur mysql : ",

    # src/fasttrack/exploits/rdpdos.py
    "Microsoft Terminal Services / Remote Desktop Services - Denial of Service": "Microsoft Terminal Services / Remote Desktop Services - Déni de service",
    "Enter the IP address to crash (remote desktop): ": "Entrez l'adresse IP à faire planter (bureau à distance) : ",

    # src/fasttrack/exploits/solarwinds.py
    "\n[*] Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit": "\n[*] Exploit par injection SQL SYSTEM distante Solarwinds Storage Manager 5.1.0",
    "[*] Vulnerability discovered by Digital Defence - DDIVRT-2011-39": "[*] Vulnérabilité découverte par Digital Defence - DDIVRT-2011-39",
    "Enter the remote host IP address: ": "Entrez l'adresse IP de l'hôte distant : ",
    "Enter the attacker IP address: ": "Entrez l'adresse IP de l'attaquant : ",
    "Enter the local port: ": "Entrez le port local : ",
    "[*] Sending evil payload": "[*] Envoi du payload malveillant",
    "[*] Triggering shell": "[*] Déclenchement du shell",
    "[*] Check your shell on {0} {1}\n": "[*] Vérifiez votre shell sur {0} {1}\n",

    # src/fasttrack/delldrac.py
    "{0}[!]{1} There are to many people logged but un: root and pw: calvin are legit on IP: {2}": "{0}[!]{1} Trop de personnes sont connectées mais le compte root / mot de passe calvin est valide sur l'IP : {2}",
    "{0}[*]{1} Dell DRAC compromised! username: root and password: calvin for IP address: {2}": "{0}[*]{1} Dell DRAC compromis ! nom d'utilisateur : root et mot de passe : calvin pour l'adresse IP : {2}",
    "{0}[*]{1} Dell Chassis compromised! username: root password: calvin for IP address: {2}": "{0}[*]{1} Dell Chassis compromis ! nom d'utilisateur : root mot de passe : calvin pour l'adresse IP : {2}",
    "Fast-Track DellDRAC and Dell Chassis Discovery and Brute Forcer": "Fast-Track - Découverte et bruteforce DellDRAC et Dell Chassis",
    "Written by Dave Kennedy @ TrustedSec": "Écrit par Dave Kennedy @ TrustedSec",
    "This attack vector can be used to identify default installations": "Ce vecteur d'attaque permet d'identifier les installations par défaut",
    "of Dell DRAC and Chassis installations. Once found, you can use": "de Dell DRAC et Chassis. Une fois trouvées, vous pouvez utiliser",
    "the remote administration capabilties to mount a virtual media": "les capacités d'administration distante pour monter un média virtuel",
    "device and use it to load for example Back|Track or password": "et l'utiliser pour charger par exemple un ISO Back|Track ou de",
    "reset iso. From there, add yourself a local administrator account": "réinitialisation de mot de passe. À partir de là, ajoutez-vous un compte",
    "or dump the SAM database. This will allow you to compromise the": "administrateur local ou extrayez la base SAM. Cela vous permettra de",
    "entire infrastructure. You will need to find a DRAC instance that": "compromettre l'infrastructure entière. Vous devrez trouver une instance DRAC",
    "has an attached server and reboot it into the iso using the virtual": "avec un serveur attaché et le redémarrer sur l'ISO via le média",
    "media device.": "virtuel.",
    "Enter the IP Address or CIDR notation below. Example: 192.168.1.1/24": "Entrez ci-dessous l'adresse IP ou la notation CIDR. Exemple : 192.168.1.1/24",
    "Enter the IP or CIDR: ": "Entrez l'IP ou le CIDR : ",
    "{0}[*]{1} Scanning IP addresses, this could take a few minutes depending on how large the subnet range...": "{0}[*]{1} Scan des adresses IP en cours, cela peut prendre quelques minutes selon la taille de la plage réseau...",
    "{0}[*]{1} Asan example, a /16 can take an hour or two.. A slash 24 is only a couple seconds. Be patient.": "{0}[*]{1} Par exemple, un /16 peut prendre une heure ou deux.. Un /24 ne prend que quelques secondes. Soyez patient.",
    "{0}[*]{1} DellDrac / Chassis Brute Forcer has finished scanning. Happy Hunting =)": "{0}[*]{1} Le bruteforceur DellDrac / Chassis a terminé le scan. Bonne chasse =)",
    "{0}[!]{1} Sorry, unable to find any of the Dell servers with default creds..Good luck :(": "{0}[!]{1} Désolé, aucun serveur Dell avec les identifiants par défaut n'a été trouvé..Bonne chance :(",
    "Press {return} to exit.": "Appuyez sur {entrée} pour sortir.",

    # src/fasttrack/mssql.py
    "Attempting to brute force {bold}{ipaddr}:{port}{endc}"
    " with username of {bold}{username}{endc}"
    " and password of {bold}{passwords}{endc}":
        "Tentative de bruteforce sur {bold}{ipaddr}:{port}{endc}"
        " avec le nom d'utilisateur {bold}{username}{endc}"
        " et le mot de passe {bold}{passwords}{endc}",
    "\nSuccessful login with username {0} and password: {1}": "\nConnexion réussie avec le nom d'utilisateur {0} et le mot de passe : {1}",
    "Unable to guess the SQL password for {0} with username of {1}": "Impossible de deviner le mot de passe SQL pour {0} avec le nom d'utilisateur {1}",
    "Enabling the xp_cmdshell stored procedure...": "Activation de la procédure stockée xp_cmdshell...",
    """Pick which deployment method to use. The first is PowerShell and should be used on any modern operating system. The second method will use the certutil method to convert a binary to a binary.\n""":
        """Choisissez la méthode de déploiement à utiliser. La première est PowerShell et doit être utilisée sur tout système moderne. La seconde méthode utilise certutil pour convertir un binaire.\n""",
    "Enter your choice:\n\n"
    "1.) Use PowerShell Injection (recommended)\n"
    "2.) Use Certutil binary conversion\n\n"
    "Enter your choice [1]:":
        "Entrez votre choix :\n\n"
        "1.) Utiliser l'injection PowerShell (recommandé)\n"
        "2.) Utiliser la conversion binaire Certutil\n\n"
        "Entrez votre choix [1] :",
    "Powershell injection was selected to deploy to the remote system (awesome).": "L'injection PowerShell a été sélectionnée pour le déploiement sur le système distant (parfait).",
    "Do you want to use powershell injection? [yes/no]:": "Voulez-vous utiliser l'injection PowerShell ? [yes/no] :",
    "Powershell delivery selected. Boom!": "Livraison PowerShell sélectionnée. Boom !",
    "Powershell not selected, using debug method.": "PowerShell non sélectionné, utilisation de la méthode debug.",
    "You can either select to use a default "
    "Metasploit payload here or import your "
    "own in order to deliver to the system. "
    "Note that if you select your own, you "
    "will need to create your own listener "
    "at the end in order to capture this.\n\n":
        "Vous pouvez soit sélectionner un payload "
        "Metasploit par défaut, soit importer le "
        "vôtre pour le livrer au système. "
        "Notez que si vous choisissez le vôtre, "
        "vous devrez créer votre propre listener "
        "à la fin pour le capturer.\n\n",
    "1.) Use Metasploit (default)\n"
    "2.) Select your own\n\n"
    "Enter your choice[1]:":
        "1.) Utiliser Metasploit (par défaut)\n"
        "2.) Sélectionner le vôtre\n\n"
        "Entrez votre choix [1] :",
    "Enter the path to your file you want to deploy to the system (ex /root/blah.exe):": "Entrez le chemin du fichier à déployer sur le système (ex /root/truc.exe) :",
    "File not found! Try again.": "Fichier introuvable ! Réessayez.",
    "Computers are hard. Find the path and try again. Defaulting to Metasploit payload.": "Les ordinateurs, c'est compliqué. Trouvez le bon chemin et réessayez. Retour au payload Metasploit par défaut.",
    "Starting the Metasploit listener...": "Démarrage du listener Metasploit...",
    "Using universal powershell x86 process downgrade attack..": "Utilisation de l'attaque universelle de downgrade de processus PowerShell x86..",
    "Prepping the payload for delivery and injecting alphanumeric shellcode...": "Préparation du payload pour la livraison et injection du shellcode alphanumérique...",
    "If you want the powershell commands and attack, "
    "they are exported to {0}":
        "Si vous voulez les commandes PowerShell et l'attaque, "
        "elles sont exportées vers {0}",
    "Waiting for the listener to start first before we continue forward...": "Attente du démarrage du listener avant de continuer...",
    "Be patient, Metasploit takes a little bit to start...": "Soyez patient, Metasploit prend un peu de temps à démarrer...",
    "Metasploit started... Waiting a couple more seconds for listener to activate..": "Metasploit démarré... Encore quelques secondes d'attente pour l'activation du listener..",
    "Sending the main payload via to be converted back to a binary.": "Envoi du payload principal pour reconversion en binaire.",
    "Dropping initial begin certificate header...": "Dépôt de l'en-tête initial du certificat...",
    "Deploying payload to victim machine (hex): {bold}{data}{endc}\n": "Déploiement du payload sur la machine victime (hex) : {bold}{data}{endc}\n",
    "Delivery complete. Converting hex back to binary format.": "Livraison terminée. Conversion de l'hexadécimal en format binaire.",
    "Dropping end header for binary format conversion...": "Dépôt de l'en-tête de fin pour la conversion au format binaire...",
    "Converting hex binary back to hex using certutil - Matthew Graeber man crush enabled.": "Conversion du binaire hex via certutil - hommage à Matthew Graeber activé.",
    "Executing the payload - magic has happened and now its time for that moment.. "
    "You know. When you celebrate. Salute to you ninja - you deserve it.":
        "Exécution du payload - la magie a eu lieu, voici le moment tant attendu.. "
        "Vous savez, celui où on célèbre. Chapeau, ninja, vous le méritez.",
    "Spawning separate child process for listener...": "Lancement d'un processus enfant séparé pour le listener...",
    "Triggering the powershell injection payload... ": "Déclenchement du payload d'injection PowerShell... ",
    "Triggering payload stager...": "Déclenchement du stager du payload...",
    "Connection established with SQL Server...": "Connexion établie avec le serveur SQL...",
    "Attempting to re-enable xp_cmdshell if disabled...": "Tentative de réactivation de xp_cmdshell s'il est désactivé...",
    "Enter your Windows Shell commands in the xp_cmdshell - prompt...": "Entrez vos commandes shell Windows dans l'invite xp_cmdshell...",

    # src/core/fasttrack.py
    "\nHere you can select either a CIDR notation/IP Address or a filename\nthat contains a list of IP Addresses.\n\nFormat for a file would be similar to this:\n\n192.168.13.25\n192.168.13.26\n192.168.13.26\n\n1. Scan IP address or CIDR\n2. Import file that contains SQL Server IP addresses\n":
        "\nVous pouvez ici sélectionner soit une notation CIDR/adresse IP, soit un nom de fichier\ncontenant une liste d'adresses IP.\n\nLe format d'un fichier ressemblerait à ceci :\n\n192.168.13.25\n192.168.13.26\n192.168.13.26\n\n1. Scanner une adresse IP ou un CIDR\n2. Importer un fichier contenant des adresses IP de serveurs SQL\n",
    "Enter your choice (ex. 1 or 2) [1]": "Entrez votre choix (ex. 1 ou 2) [1]",
    "You did not specify 1 or 2! Please try again.": "Vous n'avez pas indiqué 1 ou 2 ! Veuillez réessayer.",
    "Enter the CIDR, single IP, or multiple IPs seperated by space (ex. 192.168.1.1/24)": "Entrez le CIDR, une IP unique, ou plusieurs IP séparées par des espaces (ex. 192.168.1.1/24)",
    "Enter filename for SQL servers (ex. /root/sql.txt - note can be in format of ipaddr:port)": "Entrez le nom du fichier des serveurs SQL (ex. /root/sql.txt - peut être au format ipaddr:port)",
    "File not found! Please type in the path to the file correctly.": "Fichier introuvable ! Veuillez saisir correctement le chemin du fichier.",
    "Enter path to a wordlist file [use default wordlist]": "Entrez le chemin vers un fichier de liste de mots [liste par défaut]",
    "Enter the username to brute force or specify username file (/root/users.txt) [sa]": "Entrez le nom d'utilisateur à forcer ou indiquez un fichier d'utilisateurs (/root/users.txt) [sa]",
    "If you were using a file, its not found, using text as username.": "Si vous utilisiez un fichier, il n'a pas été trouvé ; utilisation du texte comme nom d'utilisateur.",
    "Hunting for SQL servers.. This may take a little bit.": "Recherche de serveurs SQL... Cela peut prendre un petit moment.",
    "Sorry boss. The file was not found. Try again": "Désolé chef. Le fichier n'a pas été trouvé. Réessayez",
    "Enter the CIDR, single, IP, or file with IP addresses (ex. 192.168.1.1/24)": "Entrez le CIDR, une IP unique, ou un fichier d'adresses IP (ex. 192.168.1.1/24)",
    "Atta boy. Found the file this time. Moving on.": "Bien joué. Le fichier a été trouvé cette fois. On continue.",
    "The following SQL servers and associated ports were identified:\n": "Les serveurs SQL suivants et leurs ports associés ont été identifiés :\n",
    "By pressing enter, you will begin the brute force process on all SQL accounts identified in the list above.": "En appuyant sur entrée, vous démarrerez le bruteforce sur tous les comptes SQL identifiés dans la liste ci-dessus.",
    "Press {enter} to begin the brute force process.": "Appuyez sur {entrée} pour démarrer le bruteforce.",
    "Sorry. Unable to locate or fully compromise a MSSQL Server on the following SQL servers: ": "Désolé. Impossible de localiser ou de compromettre entièrement un serveur MSSQL parmi les serveurs SQL suivants : ",
    "Sorry. Unable to find any SQL servers to attack.": "Désolé. Aucun serveur SQL à attaquer n'a été trouvé.",
    "Press {return} to continue to the main menu.": "Appuyez sur {entrée} pour revenir au menu principal.",
    "SET Fast-Track attacked the following SQL servers: ": "SET Fast-Track a attaqué les serveurs SQL suivants : ",
    "Below are the successfully compromised systems.\nSelect the compromise SQL server you want to interact with:\n": "Voici les systèmes compromis avec succès.\nSélectionnez le serveur SQL compromis avec lequel vous voulez interagir :\n",
    "\n   99. Return back to the main menu.\n": "\n   99. Retour au menu principal.\n",
    "Select the SQL server to interact with [1]": "Sélectionnez le serveur SQL avec lequel interagir [1]",
    "\nHow do you want to deploy the binary via debug (win2k, winxp, win2003) and/or powershell (vista,win7,2008,2012) or just a shell\n\n   1. Deploy Backdoor to System\n   2. Standard Windows Shell\n\n   99. Return back to the main menu.\n":
        "\nComment voulez-vous déployer le binaire : via debug (win2k, winxp, win2003) et/ou powershell (vista, win7, 2008, 2012), ou juste un shell\n\n   1. Déployer une porte dérobée sur le système\n   2. Shell Windows standard\n\n   99. Retour au menu principal.\n",
    "Which deployment option do you want [1]": "Quelle option de déploiement voulez-vous [1]",
    "Enter the hostname or IP address of the SQL server": "Entrez le nom d'hôte ou l'adresse IP du serveur SQL",
    "Enter the SQL port to connect [1433]": "Entrez le port SQL de connexion [1433]",
    "Enter the username of the SQL Server [sa]": "Entrez le nom d'utilisateur du serveur SQL [sa]",
    "Enter the password for the SQL server": "Entrez le mot de passe du serveur SQL",
    "Connecting to the SQL server...": "Connexion au serveur SQL...",
    "Connection to SQL Server failed. Try again.": "La connexion au serveur SQL a échoué. Réessayez.",
    "Dropping into a SQL shell. Type quit to exit.": "Ouverture d'un shell SQL. Tapez quit pour sortir.",
    "Enter your SQL command here: ": "Entrez votre commande SQL ici : ",
    "Exiting the SQL shell and returning to menu.": "Fermeture du shell SQL et retour au menu.",
    "\nIncorrect syntax somewhere. Printing error message: ": "\nSyntaxe incorrecte quelque part. Affichage du message d'erreur : ",
    "Select the number of the exploit you want": "Sélectionnez le numéro de l'exploit que vous voulez",
    "\nRID_ENUM is a tool that will enumerate user accounts through a rid cycling attack through null sessions. In\norder for this to work, the remote server will need to have null sessions enabled. In most cases, you would use\nthis against a domain controller on an internal penetration test. You do not need to provide credentials, it will\nattempt to enumerate the base RID address and then cycle through 500 (Administrator) to whatever RID you want.":
        "\nRID_ENUM est un outil qui énumère les comptes utilisateurs via une attaque de cycling de RID à travers des sessions nulles.\nPour que cela fonctionne, le serveur distant doit avoir les sessions nulles activées. Dans la plupart des cas, on\nutilise ceci contre un contrôleur de domaine lors d'un test d'intrusion interne. Vous n'avez pas besoin de fournir\nd'identifiants, l'outil tentera d'énumérer l'adresse RID de base puis de parcourir de 500 (Administrateur) jusqu'au RID souhaité.",
    "Enter the IP address of server (or quit to exit)": "Entrez l'adresse IP du serveur (ou quit pour sortir)",
    "Next you can automatically brute force the user accounts. If you do not want to brute force, type no at the next prompt": "Vous pouvez ensuite forcer automatiquement les comptes utilisateurs. Si vous ne voulez pas le faire, tapez no à la prochaine invite",
    "Enter path to dictionary file to brute force [enter for built in]": "Entrez le chemin du fichier dictionnaire pour le bruteforce [entrée pour celui intégré]",
    "No problem, not brute forcing user accounts": "Aucun problème, pas de bruteforce sur les comptes utilisateurs",
    "You are about to brute force user accounts, be careful for lockouts.": "Vous êtes sur le point de forcer les comptes utilisateurs, attention aux verrouillages de compte.",
    "Are you sure you want to brute force [yes/no]": "Êtes-vous sûr de vouloir lancer le bruteforce [yes/no]",
    "Okay. Not brute forcing user accounts *phew*.": "D'accord. Pas de bruteforce sur les comptes utilisateurs *ouf*.",
    "What RID do you want to start at [500]": "À quel RID voulez-vous commencer [500]",
    "What RID do you want to stop at [15000]": "À quel RID voulez-vous arrêter [15000]",
    "Launching RID_ENUM to start enumerating user accounts...": "Lancement de RID_ENUM pour commencer l'énumération des comptes utilisateurs...",
    "Everything is finished!": "Tout est terminé !",
    "Press {return} to go back to the main menu.": "Appuyez sur {entrée} pour revenir au menu principal.",
    "\nPSEXEC Powershell Injection Attack:\n\nThis attack will inject a meterpreter backdoor through powershell memory injection. This will circumvent\nAnti-Virus since we will never touch disk. Will require Powershell to be installed on the remote victim\nmachine. You can use either straight passwords or hash values.\n":
        "\nAttaque par injection PowerShell PSEXEC :\n\nCette attaque injecte une porte dérobée meterpreter via une injection mémoire PowerShell. Cela permet de contourner\nl'antivirus puisque le disque n'est jamais touché. Nécessite que PowerShell soit installé sur la machine victime\ndistante. Vous pouvez utiliser soit des mots de passe en clair, soit des valeurs de hash.\n",

    # src/core/setcore.py
    "valid responses are 'n|y|N|Y|no|yes|No|Yes|NO|YES'": "les réponses valides sont 'n|y|N|Y|no|yes|No|Yes|NO|YES'",
    "\n      Press ": "\n      Appuyez sur ",
    "<return> ": "<entrée> ",
    "to continue": "pour continuer",
    "\n  99) Return to Main Menu\n": "\n  99) Retour au menu principal\n",
    "This is not a valid IP address...": "Ceci n'est pas une adresse IP valide...",
    "Site has been successfully cloned and is: ": "Le site a été cloné avec succès et se trouve ici : ",
    "{blue}\n"
    "[---]        The Social-Engineer Toolkit ({yellow}SET{blue})         [---]\n"
    "[---]        Created by:{red} David Kennedy {blue}({yellow}ReL1K{blue})         [---]\n"
    "                      Version: {red}{version}{blue}\n"
    "                    Codename: '{yellow}Maverick{endc}{blue}'\n"
    "[---]        Follow us on Twitter: {purple}@TrustedSec{blue}         [---]\n"
    "[---]        Follow me on Twitter: {purple}@HackingDave{blue}        [---]\n"
    "[---]       Homepage: {yellow}https://www.trustedsec.com{blue}       [---]\n"
    "{green}        Welcome to the Social-Engineer Toolkit (SET).\n"
    "         The one stop shop for all of your SE needs.\n":
        "{blue}\n"
        "[---]        The Social-Engineer Toolkit ({yellow}SET{blue})         [---]\n"
        "[---]        Créé par :{red} David Kennedy {blue}({yellow}ReL1K{blue})         [---]\n"
        "                      Version : {red}{version}{blue}\n"
        "                    Nom de code : '{yellow}Maverick{endc}{blue}'\n"
        "[---]        Suivez-nous sur Twitter : {purple}@TrustedSec{blue}         [---]\n"
        "[---]        Suivez-moi sur Twitter : {purple}@HackingDave{blue}        [---]\n"
        "[---]       Site web : {yellow}https://www.trustedsec.com{blue}       [---]\n"
        "{green}        Bienvenue dans le Social-Engineer Toolkit (SET).\n"
        "         La solution unique pour tous vos besoins en ingénierie sociale.\n",
    "   The Social-Engineer Toolkit is a product of TrustedSec.\n\n           Visit: ": "   Le Social-Engineer Toolkit est un produit de TrustedSec.\n\n           Visitez : ",
    "   It's easy to update using the PenTesters Framework! (PTF)\nVisit ": "   Il est facile de le mettre à jour avec le PenTesters Framework ! (PTF)\nVisitez ",
    " to update all your tools!\n\n": " pour mettre à jour tous vos outils !\n\n",
    "          There is a new version of SET available.\n                    ": "          Une nouvelle version de SET est disponible.\n                    ",
    " Your version: ": " Votre version : ",
    "\n                  Current version: ": "\n                  Version actuelle : ",
    "\n\nPlease update SET to the latest before submitting any git issues.\n\n": "\n\nVeuillez mettre à jour SET vers la dernière version avant de soumettre une issue git.\n\n",
    " Unable to check for new version of SET (is your network up?)\n": " Impossible de vérifier la présence d'une nouvelle version de SET (votre réseau fonctionne-t-il ?)\n",
    "\n\n Thank you for ": "\n\n Merci d'avoir ",
    "shopping": "fait vos achats",
    " with the Social-Engineer Toolkit.\n\n Hack the Gibson...and remember...hugs are worth more than handshakes.\n": " avec le Social-Engineer Toolkit.\n\n Hack the Gibson... et souvenez-vous... les câlins valent plus que les poignées de main.\n",

    # setoolkit
    "\n The Social-Engineer Toolkit (SET) - by David Kennedy (ReL1K)": "\n The Social-Engineer Toolkit (SET) - par David Kennedy (ReL1K)",
    "\n Not running as root. \n\nExiting the Social-Engineer Toolkit (SET).\n": "\n N'est pas exécuté en tant que root. \n\nFermeture du Social-Engineer Toolkit (SET).\n",
    "[*] Overwriting old config for updates to SET. Backing up your old one in /etc/setoolkit/": "[*] Remplacement de l'ancienne configuration pour les mises à jour de SET. Sauvegarde de l'ancienne dans /etc/setoolkit/",
    "[!] The python-pycrypto python module not installed. You will lose the ability to use multi-pyinjector.": "[!] Le module python-pycrypto n'est pas installé. Vous perdrez la possibilité d'utiliser multi-pyinjector.",
    "{0}The Social-Engineer Toolkit is designed purely"
    " for good and not evil. If you are planning on "
    "using this tool for malicious purposes that are "
    "not authorized by the company you are performing "
    "assessments for, you are violating the terms of "
    "service and license of this toolset. By hitting "
    "yes (only one time), you agree to the terms of "
    "service and that you will only use this tool for "
    "lawful purposes only.{1}":
        "{0}Le Social-Engineer Toolkit est conçu uniquement"
        " pour le bien, et non pour le mal. Si vous envisagez "
        "d'utiliser cet outil à des fins malveillantes qui ne "
        "sont pas autorisées par l'entreprise pour laquelle vous "
        "réalisez des évaluations, vous violez les conditions "
        "d'utilisation et la licence de cet outil. En répondant "
        "oui (une seule fois), vous acceptez les conditions "
        "d'utilisation et vous vous engagez à n'utiliser cet outil "
        "que dans un cadre légal.{1}",
    "\nDo you agree to the terms of service [y/n]: ": "\nAcceptez-vous les conditions d'utilisation [o/n] : ",
    "[!] Exiting the Social-Engineer Toolkit, have a nice day.": "[!] Fermeture du Social-Engineer Toolkit, bonne journée.",
    "\n  99) Exit the Social-Engineer Toolkit\n": "\n  99) Quitter le Social-Engineer Toolkit\n",
    "Have you given someone a hug today? Remember a hug can change the world.": "Avez-vous fait un câlin à quelqu'un aujourd'hui ? Rappelez-vous qu'un câlin peut changer le monde.",
    "\nPlease give someone a hug then press {return} to continue.": "\nFaites un câlin à quelqu'un puis appuyez sur {entrée} pour continuer.",
    "HUGS ARE ALWAYS FREE! NEVER CHARGE! ALWAYS HUG.": "LES CÂLINS SONT TOUJOURS GRATUITS ! NE FACTUREZ JAMAIS ! FAITES TOUJOURS DES CÂLINS.",
    "\nDo not press return until giving someone a hug.": "\nN'appuyez pas sur entrée avant d'avoir fait un câlin à quelqu'un.",
    "YAYYYYYYYYYYYYYYYYYYYYYY DerbyCon.\n\nDerbyCon 7.0 'Legacy' -- September 22th - 24th 2017": "YAYYYYYYYYYYYYYYYYYYYYYY DerbyCon.\n\nDerbyCon 7.0 'Legacy' -- 22 au 24 septembre 2017",
    "\nDon't miss it! Sep 23 - Sep 25th! Press {return} to continue.": "\nNe le manquez pas ! Du 23 au 25 septembre ! Appuyez sur {entrée} pour continuer.",
    "We miss you buddy. David Jones (Rance) changed a lot of us and you'll always be apart of our lives (and SET). Fuck Cancer.": "Tu nous manques, pote. David Jones (Rance) a changé beaucoup d'entre nous et tu feras toujours partie de nos vies (et de SET). Fuck le cancer.",
    "Press {return} to continue.": "Appuyez sur {entrée} pour continuer.",
    "2015-2016 CHAMPS BABY!!! C l e e e e e  e v  eeee l a a n n d d d d d d d d d d d ": "CHAMPIONS 2015-2016 BABY !!! C l e e e e e  e v  eeee l a a n n d d d d d d d d d d d ",
    "\n\nThank you for {0}shopping{1} with the Social-Engineer Toolkit."
    "\n\nHack the Gibson...and remember...hugs are worth more "
    "than handshakes.\n":
        "\n\nMerci d'avoir {0}fait vos achats{1} avec le Social-Engineer Toolkit."
        "\n\nHack the Gibson... et souvenez-vous... les câlins valent plus "
        "que les poignées de main.\n",
    "\n\n[!] Something went wrong, printing the error: ": "\n\n[!] Quelque chose s'est mal passé, affichage de l'erreur : ",

    # src/core/set.py
    "\n The Social-Engineer Toolkit (SET) - by David Kennedy (ReL1K)": "\n The Social-Engineer Toolkit (SET) - par David Kennedy (ReL1K)",
    "\n Not running as root. \n\nExiting the Social-Engineer Toolkit (SET).\n": "\n N'est pas exécuté en tant que root. \n\nFermeture du Social-Engineer Toolkit (SET).\n",
    "\n  99) Return back to the main menu.\n": "\n  99) Retour au menu principal.\n",
    "Sorry. This feature is not yet supported in Windows or Metasploit was not found.": "Désolé. Cette fonctionnalité n'est pas encore prise en charge sous Windows, ou Metasploit n'a pas été trouvé.",
    "Sorry. This option is not yet available in Windows or Metasploit was not found.": "Désolé. Cette option n'est pas encore disponible sous Windows, ou Metasploit n'a pas été trouvé.",
    "ERROR:Invalid selection, going back to menu.": "ERREUR : sélection invalide, retour au menu.",
    "Invalid option": "Option invalide",
    "  99) Return to Webattack Menu\n": "  99) Retour au menu Web Attack\n",
    "\n Sorry, you can't use the Web Jacking vector with Web Templates.": "\n Désolé, vous ne pouvez pas utiliser le vecteur Web Jacking avec les modèles web.",
    "\n Sorry, you can't use the Multi-Attack vector with Web Templates.": "\n Désolé, vous ne pouvez pas utiliser le vecteur multi-attaques avec les modèles web.",
    "\n Sorry, you can only use the cloner option with the tabnabbing method.": "\n Désolé, vous ne pouvez utiliser l'option de clonage qu'avec la méthode tabnabbing.",
    "Credential harvester will allow you to utilize the clone capabilities within SET": "Le Credential Harvester vous permet d'utiliser les capacités de clonage de SET",
    "to harvest credentials or parameters from a website as well as place them into a report": "pour récupérer des identifiants ou des paramètres d'un site web et les intégrer dans un rapport",
    "Your interface IP Address": "L'adresse IP de votre interface",
    "NAT/Port Forwarding can be used in the cases where your SET machine is": "Le NAT/Port Forwarding peut être utilisé dans les cas où votre machine SET",
    "not externally exposed and may be a different IP address than your reverse listener.": "n'est pas exposée en externe et peut avoir une adresse IP différente de celle de votre listener inversé.",
    "Are you using NAT/Port Forwarding [yes|no]": "Utilisez-vous le NAT/Port Forwarding [yes|no]",
    "IP address to SET web server (this could be your external IP or hostname)": "Adresse IP du serveur web SET (peut être votre IP externe ou votre nom d'hôte)",
    "Is your payload handler (metasploit) on a different IP from your external NAT/Port FWD address [yes|no]": "Votre gestionnaire de payload (metasploit) est-il sur une IP différente de votre adresse NAT/Port FWD externe [yes|no]",
    "IP address for the reverse handler (reverse payload)": "Adresse IP pour le gestionnaire inversé (reverse payload)",
    "\n-------------------------------------------------------------------------------\n--- * IMPORTANT * READ THIS BEFORE ENTERING IN THE IP ADDRESS * IMPORTANT * ---\n\nThe way that this works is by cloning a site and looking for form fields to\nrewrite. If the POST fields are not usual methods for posting forms this\ncould fail. If it does, you can always save the HTML, rewrite the forms to\nbe standard forms and use the \"IMPORT\" feature. Additionally, really\nimportant:\n\nIf you are using an EXTERNAL IP ADDRESS, you need to place the EXTERNAL\nIP address below, not your NAT address. Additionally, if you don't know\nbasic networking concepts, and you have a private IP address, you will\nneed to do port forwarding to your NAT IP address from your external IP\naddress. A browser doesn’t know how to communicate with a private IP\naddress, so if you don't specify an external IP address if you are using\nthis from an external perspective, it will not work. This isn't a SET issue\nthis is how networking works.\n":
        "\n-------------------------------------------------------------------------------\n--- * IMPORTANT * LISEZ CECI AVANT DE SAISIR L'ADRESSE IP * IMPORTANT * ---\n\nLe fonctionnement consiste à cloner un site et à rechercher les champs de\nformulaire à réécrire. Si les champs POST ne suivent pas les méthodes\nhabituelles d'envoi de formulaires, cela peut échouer. Si c'est le cas, vous\npouvez toujours enregistrer le HTML, réécrire les formulaires sous une forme\nstandard et utiliser la fonctionnalité \"IMPORT\". De plus, point vraiment\nimportant :\n\nSi vous utilisez une ADRESSE IP EXTERNE, vous devez indiquer ci-dessous\nl'adresse IP EXTERNE, et non votre adresse NAT. De plus, si vous ne connaissez\npas les bases du réseau et que vous avez une adresse IP privée, vous devrez\nfaire du port forwarding vers votre adresse IP NAT depuis votre adresse IP\nexterne. Un navigateur ne sait pas communiquer avec une adresse IP privée ;\ndonc si vous ne précisez pas d'adresse IP externe alors que vous utilisez\nceci depuis une perspective externe, cela ne fonctionnera pas. Ce n'est pas\nun problème de SET, c'est ainsi que fonctionne le réseau.\n",
    "IP address for the POST back in Harvester/Tabnabbing [": "Adresse IP pour le retour POST dans Harvester/Tabnabbing [",
    "Enter the IP address for POST back in Harvester/Tabnabbing: ": "Entrez l'adresse IP pour le retour POST dans Harvester/Tabnabbing : ",
    "Automatically starting Apache for you...": "Démarrage automatique d'Apache pour vous...",
    "SET supports both HTTP and HTTPS": "SET prend en charge aussi bien HTTP que HTTPS",
    "Example: http://www.thisisafakesite.com": "Exemple : http://www.cesituestfactice.com",
    "Enter the url to clone": "Entrez l'URL à cloner",
    "Example: /home/website/ (make sure you end with /)": "Exemple : /home/website/ (assurez-vous de terminer par /)",
    "Also note that there MUST be an index.html in the folder you point to.": "Notez aussi qu'il DOIT y avoir un fichier index.html dans le dossier que vous indiquez.",
    "Path to the website to be cloned": "Chemin vers le site web à cloner",
    "ERROR:index.html not found!!": "ERREUR : index.html introuvable !!",
    "ERROR:Did you just put the path in, not file?": "ERREUR : avez-vous indiqué le chemin d'un dossier plutôt qu'un fichier ?",
    "Exiting the Social-Engineer Toolkit...Hack the Gibson.\n": "Fermeture du Social-Engineer Toolkit... Hack the Gibson.\n",
    "Index.html found. Do you want to copy the entire folder or just index.html?": "Index.html trouvé. Voulez-vous copier tout le dossier ou juste index.html ?",
    "\n1. Copy just the index.html\n2. Copy the entire folder\n\nEnter choice [1/2]: ": "\n1. Copier seulement index.html\n2. Copier tout le dossier\n\nFaites votre choix [1/2] : ",
    "You cannot specify a folder in the default SET path. This goes into a loop Try something different.": "Vous ne pouvez pas indiquer un dossier dans le chemin par défaut de SET. Cela créerait une boucle. Essayez autre chose.",
    "Enter the folder to import into SET, this CANNOT be the SET directory: ": "Entrez le dossier à importer dans SET, cela NE PEUT PAS être le dossier de SET : ",
    "You tried the same thing. Exiting now.": "Vous avez tenté la même chose. Fermeture en cours.",
    "Example: http://www.blah.com": "Exemple : http://www.truc.com",
    "URL of the website you imported": "URL du site web que vous avez importé",
    " Returning to main menu.\n": " Retour au menu principal.\n",
    " Control-C detected, bombing out to previous menu..": " Control-C détecté, retour au menu précédent..",
    "IP address for the reverse connection (payload)": "Adresse IP pour la connexion inversée (payload)",
    "Do you want to create a payload and listener [yes|no]: ": "Voulez-vous créer un payload et un listener [yes|no] : ",
    "Generating the SD2Teensy OSX ino file for you...": "Génération du fichier ino SD2Teensy OSX pour vous...",
    "File has been exported to ~/.set/reports/osx_sd2teensy/osx_sd2teensy.ino": "Le fichier a été exporté vers ~/.set/reports/osx_sd2teensy/osx_sd2teensy.ino",
    "Generating the Arduino sniffer and libraries ino..": "Génération du fichier ino du sniffer Arduino et des bibliothèques..",
    "Arduino sniffer files and libraries exported to ~/.set/reports/arduino_sniffer": "Fichiers et bibliothèques du sniffer Arduino exportés vers ~/.set/reports/arduino_sniffer",
    "Generating the Arduino jammer ino and libraries...": "Génération du fichier ino du jammer Arduino et des bibliothèques...",
    "Arduino jammer files and libraries exported to ~/.set/reports/arduino_jammer": "Fichiers et bibliothèques du jammer Arduino exportés vers ~/.set/reports/arduino_jammer",
    "Generating the Powershell - Shellcode injection ino..": "Génération du fichier ino d'injection Shellcode PowerShell..",
    "HID Msbuild compile to memory Shellcode Attack selected": "Attaque HID Msbuild compilation en mémoire Shellcode sélectionnée",
    "Sorry. The wireless attack vector is not yet supported in Windows.": "Désolé. Le vecteur d'attaque sans fil n'est pas encore pris en charge sous Windows.",
    "Warning airbase-ng was not detected on your system. Using one in SET.": "Attention, airbase-ng n'a pas été détecté sur votre système. Utilisation de celui fourni dans SET.",
    "If you experience issues, you should install airbase-ng on your system.": "Si vous rencontrez des problèmes, vous devriez installer airbase-ng sur votre système.",
    "You can configure it through the set_config and point to airbase-ng.": "Vous pouvez le configurer via set_config en indiquant le chemin vers airbase-ng.",
    " [*] Returning to the main menu ...": " [*] Retour au menu principal ...",
    "ERROR:DNS Spoof was not detected. Check the set_config file.": "ERREUR : DNS Spoof n'a pas été détecté. Vérifiez le fichier set_config.",
    "\nThe QRCode Attack Vector will create a QRCode for you with whatever URL you want.\n\nWhen you have the QRCode Generated, select an additional attack vector within SET and\ndeploy the QRCode to your victim. For example, generate a QRCode of the SET Java Applet\nand send the QRCode via a mailer.\n":
        "\nLe vecteur d'attaque QRCode va créer pour vous un QRCode avec l'URL de votre choix.\n\nUne fois le QRCode généré, sélectionnez un vecteur d'attaque supplémentaire dans SET et\ndéployez le QRCode vers votre victime. Par exemple, générez un QRCode de l'Applet Java\nde SET et envoyez le QRCode par email.\n",
    "Enter the URL you want the QRCode to go to (99 to exit): ": "Entrez l'URL vers laquelle le QRCode doit pointer (99 pour sortir) : ",
    "This module requires PIL (Or Pillow) and qrcode to work properly.": "Ce module nécessite PIL (ou Pillow) et qrcode pour fonctionner correctement.",
    "Just do pip install Pillow; pip install qrcode": "Faites simplement pip install Pillow; pip install qrcode",
    "Else refer to here for installation: http://pillow.readthedocs.io/en/3.3.x/installation.html": "Sinon, référez-vous à ceci pour l'installation : http://pillow.readthedocs.io/en/3.3.x/installation.html",

    # src/core/menu/text.py
    'Port cannot be zero!': 'Le port ne peut pas être zéro !',
    "Let's stick with the LOWER 65,535 ports...": 'Restons sur des ports INFÉRIEURS à 65 535...',
    ' Select from the menu:\n': ' Sélectionnez dans le menu :\n',
    '\n The first method will allow SET to import a list of pre-defined web\n applications that it can utilize within the attack.\n\n The second method will completely clone a website of your choosing\n and allow you to utilize the attack vectors within the completely\n same web application you were attempting to clone.\n\n The third method allows you to import your own website, note that you\n should only have an index.html when using the import website\n functionality.\n   ': "\n La première méthode permet à SET d'importer une liste d'applications\n web prédéfinies qu'il peut utiliser dans l'attaque.\n\n La deuxième méthode clone entièrement un site web de votre choix\n et vous permet d'utiliser les vecteurs d'attaque au sein de\n l'application web identique que vous souhaitiez cloner.\n\n La troisième méthode vous permet d'importer votre propre site web ; notez\n que vous ne devez avoir qu'un fichier index.html lors de l'utilisation\n de la fonctionnalité d'import de site web.\n   ",
    '\nWhat payload would you like to generate:\n\n  Name:                                       Description:\n': '\nQuel payload souhaitez-vous générer :\n\n  Nom :                                       Description :\n',
    '\n Select the file format exploit you want.\n The default is the PDF embedded EXE.\n\n           ********** PAYLOADS **********\n': "\n Sélectionnez l'exploit de type fichier que vous voulez.\n Par défaut, il s'agit de l'EXE intégré dans un PDF.\n\n           ********** PAYLOADS **********\n",
    '\n Enter the browser exploit you would like to use [8]:\n': "\n Entrez l'exploit navigateur que vous souhaitez utiliser [8] :\n",
    "\nSelect one of the below, 'backdoored executable' is typically the best. However,\nmost still get picked up by AV. You may need to do additional packing/crypting\nin order to get around basic AV detection.\n": '\nSélectionnez l\'une des options ci-dessous ; "exécutable piégé" est généralement la meilleure.\nCependant, la plupart sont encore détectés par les antivirus. Il peut être nécessaire d\'effectuer\nun packing/chiffrement supplémentaire pour contourner la détection antivirus de base.\n',
    '\n The DLL Hijacker vulnerability will allow normal file extensions to\n call local (or remote) .dll files that can then call your payload or\n executable. In this scenario it will compact the attack in a zip file\n and when the user opens the file extension, will trigger the dll then\n ultimately our payload. During the time of this release, all of these\n file extensions were tested and appear to work and are not patched. This\n will continuously be updated as time goes on.\n': "\n La vulnérabilité DLL Hijacker permet à des extensions de fichiers normales\n d'appeler des fichiers .dll locaux (ou distants) qui peuvent ensuite appeler\n votre payload ou exécutable. Dans ce scénario, l'attaque sera compactée dans\n un fichier zip et, lorsque l'utilisateur ouvrira l'extension de fichier,\n déclenchera la DLL puis finalement notre payload. Au moment de cette version,\n toutes ces extensions de fichiers ont été testées et semblent fonctionner et\n ne sont pas corrigées. Cette liste sera mise à jour continuellement avec le temps.\n",
    'Please choose the DHCP configuration you would like to use: ': 'Veuillez choisir la configuration DHCP que vous souhaitez utiliser : ',
    'Social-Engineering Attacks': "Attaques d'ingénierie sociale",
    'Penetration Testing (Fast-Track)': "Tests d'intrusion (Fast-Track)",
    'Third Party Modules': 'Modules tiers',
    'Update the Social-Engineer Toolkit': 'Mettre à jour le Social-Engineer Toolkit',
    'Update SET configuration': 'Mettre à jour la configuration de SET',
    'Help, Credits, and About': 'Aide, crédits et à propos',
    'Spear-Phishing Attack Vectors': "Vecteurs d'attaque par spear-phishing",
    'Website Attack Vectors': "Vecteurs d'attaque par site web",
    'Infectious Media Generator': 'Générateur de média infecté',
    'Create a Payload and Listener': 'Créer un payload et un listener',
    'Mass Mailer Attack': "Attaque par envoi massif d'emails",
    'Arduino-Based Attack Vector': "Vecteur d'attaque basé sur Arduino",
    'Wireless Access Point Attack Vector': "Vecteur d'attaque par point d'accès sans fil",
    'QRCode Generator Attack Vector': "Vecteur d'attaque par génération de QRCode",
    'Powershell Attack Vectors': "Vecteurs d'attaque PowerShell",
    'Perform a Mass Email Attack': 'Effectuer une attaque par email massif',
    'Create a FileFormat Payload': 'Créer un payload de type FileFormat',
    'Create a Social-Engineering Template': "Créer un modèle d'ingénierie sociale",
    'Java Applet Attack Method': 'Attaque par Applet Java',
    'Metasploit Browser Exploit Method': 'Attaque par exploit navigateur Metasploit',
    'Credential Harvester Attack Method': "Attaque par récupération d'identifiants (Credential Harvester)",
    'Tabnabbing Attack Method': 'Attaque par Tabnabbing',
    'Web Jacking Attack Method': 'Attaque par Web Jacking',
    'Multi-Attack Web Method': 'Attaque Web multi-méthodes',
    'HTA Attack Method': 'Attaque HTA',
    'Microsoft SQL Bruter': 'Bruteforce Microsoft SQL',
    'Custom Exploits': 'Exploits personnalisés',
    'SCCM Attack Vector': "Vecteur d'attaque SCCM",
    'Dell DRAC/Chassis Default Checker': 'Vérificateur de mots de passe par défaut Dell DRAC/Chassis',
    'RID_ENUM - User Enumeration Attack': "RID_ENUM - Attaque d'énumération des utilisateurs",
    'PSEXEC Powershell Injection': 'Injection PowerShell via PSEXEC',
    'MS08-067 (Win2000, Win2k3, WinXP)': 'MS08-067 (Win2000, Win2k3, WinXP)',
    'Mozilla Firefox 3.6.16 mChannel Object Use After Free Exploit (Win7)': "Mozilla Firefox 3.6.16 - Exploit Use After Free sur l'objet mChannel (Win7)",
    'Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit': 'Solarwinds Storage Manager 5.1.0 - Injection SQL SYSTEM distante',
    'RDP | Use after Free - Denial of Service': 'RDP | Use after Free - Déni de service',
    'MySQL Authentication Bypass Exploit': "Contournement d'authentification MySQL",
    'F5 Root Authentication Bypass Exploit': "Contournement d'authentification root F5",
    'Scan and Attack MSSQL': 'Scanner et attaquer MSSQL',
    'Connect directly to MSSQL': 'Se connecter directement à MSSQL',
    'Web Templates': 'Modèles web',
    'Site Cloner': 'Cloneur de site',
    'Custom Import\n': 'Import personnalisé\n',
    'PowerShell HTTP GET MSF Payload': 'Payload MSF PowerShell HTTP GET',
    'WSCRIPT HTTP GET MSF Payload': 'Payload MSF WSCRIPT HTTP GET',
    'PowerShell based Reverse Shell Payload': 'Payload Reverse Shell basé sur PowerShell',
    'Internet Explorer/FireFox Beef Jack Payload': 'Payload Beef Jack pour Internet Explorer/FireFox',
    'Go to malicious java site and accept applet Payload': "Payload : aller sur un site Java malveillant et accepter l'applet",
    'Gnome wget Download Payload': 'Payload Gnome wget Download',
    'Binary 2 Teensy Attack (Deploy MSF payloads)': 'Attaque Binaire vers Teensy (déploie des payloads MSF)',
    'SDCard 2 Teensy Attack (Deploy Any EXE)': "Attaque SDCard vers Teensy (déploie n'importe quel EXE)",
    'SDCard 2 Teensy Attack (Deploy on OSX)': 'Attaque SDCard vers Teensy (déploie sur OSX)',
    'X10 Arduino Sniffer PDE and Libraries': 'PDE et bibliothèques du Sniffer X10 Arduino',
    'X10 Arduino Jammer PDE and Libraries': 'PDE et bibliothèques du Jammer X10 Arduino',
    'PowerShell Direct ShellCode Teensy Attack': 'Attaque Teensy ShellCode direct via PowerShell',
    'Peensy Multi Attack Dip Switch + SDCard Attack': 'Attaque Peensy multi-attaque Dip Switch + SDCard',
    'HID Msbuild compile to memory Shellcode Attack': 'Attaque HID Msbuild compilation en mémoire Shellcode',
    'Start the SET Wireless Attack Vector Access Point': "Démarrer le point d'accès du vecteur d'attaque sans fil SET",
    'Stop the SET Wireless Attack Vector Access Point': "Arrêter le point d'accès du vecteur d'attaque sans fil SET",
    'File-Format Exploits': 'Exploits de type FileFormat',
    'Standard Metasploit Executable': 'Exécutable Metasploit standard',
    'Windows Shell Reverse_TCP               Spawn a command shell on victim and send back to attacker': "Windows Shell Reverse_TCP               Lance un shell de commandes sur la victime et le renvoie à l'attaquant",
    'Windows Reverse_TCP Meterpreter         Spawn a meterpreter shell on victim and send back to attacker': "Windows Reverse_TCP Meterpreter         Lance un shell Meterpreter sur la victime et le renvoie à l'attaquant",
    'Windows Reverse_TCP VNC DLL             Spawn a VNC server on victim and send back to attacker': "Windows Reverse_TCP VNC DLL             Lance un serveur VNC sur la victime et le renvoie à l'attaquant",
    'Windows Shell Reverse_TCP X64           Windows X64 Command Shell, Reverse TCP Inline': 'Windows Shell Reverse_TCP X64           Shell de commandes Windows X64, Reverse TCP Inline',
    'Windows Meterpreter Reverse_TCP X64     Connect back to the attacker (Windows x64), Meterpreter': "Windows Meterpreter Reverse_TCP X64     Connexion retour vers l'attaquant (Windows x64), Meterpreter",
    'Windows Meterpreter Egress Buster       Spawn a Meterpreter shell and find a port home via multiple ports': 'Windows Meterpreter Egress Buster       Lance un shell Meterpreter et trouve un port de sortie parmi plusieurs ports',
    'Windows Meterpreter Reverse HTTPS       Tunnel communication over HTTP using SSL and use Meterpreter': 'Windows Meterpreter Reverse HTTPS       Tunnelise la communication via HTTP avec SSL et utilise Meterpreter',
    'Windows Meterpreter Reverse DNS         Use a hostname instead of an IP address and use Reverse Meterpreter': "Windows Meterpreter Reverse DNS         Utilise un nom d'hôte plutôt qu'une adresse IP et utilise Reverse Meterpreter",
    'Download/Run your Own Executable        Downloads an executable and runs it\n': "Télécharger/Exécuter votre propre exécutable        Télécharge un exécutable et l'exécute\n",
    'Windows Reverse TCP Shell              Spawn a command shell on victim and send back to attacker': "Windows Reverse TCP Shell              Lance un shell de commandes sur la victime et le renvoie à l'attaquant",
    'Windows Meterpreter Reverse_TCP        Spawn a Meterpreter shell on victim and send back to attacker': "Windows Meterpreter Reverse_TCP        Lance un shell Meterpreter sur la victime et le renvoie à l'attaquant",
    'Windows Reverse VNC DLL                Spawn a VNC server on victim and send back to attacker': "Windows Reverse VNC DLL                Lance un serveur VNC sur la victime et le renvoie à l'attaquant",
    'Windows Reverse TCP Shell (x64)        Windows X64 Command Shell, Reverse TCP Inline': 'Windows Reverse TCP Shell (x64)        Shell de commandes Windows X64, Reverse TCP Inline',
    'Windows Meterpreter Reverse_TCP (X64)  Connects back to the attacker (Windows x64), Meterpreter': "Windows Meterpreter Reverse_TCP (X64)  Connexion retour vers l'attaquant (Windows x64), Meterpreter",
    'Windows Shell Bind_TCP (X64)           Execute payload and create an accepting port on remote system': 'Windows Shell Bind_TCP (X64)           Exécute le payload et crée un port en écoute sur le système distant',
    'Windows Meterpreter Reverse HTTPS      Tunnel communication over HTTP using SSL and use Meterpreter\n': 'Windows Meterpreter Reverse HTTPS      Tunnelise la communication via HTTP avec SSL et utilise Meterpreter\n',
    'SET Custom Written DLL Hijacking Attack Vector (RAR, ZIP)': "Vecteur d'attaque DLL Hijacking personnalisé SET (RAR, ZIP)",
    'SET Custom Written Document UNC LM SMB Capture Attack': 'Attaque par capture UNC LM SMB sur document personnalisée SET',
    'MS15-100 Microsoft Windows Media Center MCL Vulnerability': 'MS15-100 Vulnérabilité Microsoft Windows Media Center MCL',
    'MS14-017 Microsoft Word RTF Object Confusion (2014-04-01)': "MS14-017 Confusion d'objet RTF dans Microsoft Word (2014-04-01)",
    'Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow': 'Dépassement de pile Microsoft Windows CreateSizedDIBSECTION',
    'Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)': 'Dépassement de pile RTF pFragments de Microsoft Word (MS10-087)',
    'Adobe Flash Player "Button" Remote Code Execution': 'Exécution de code à distance Adobe Flash Player "Button"',
    'Adobe CoolType SING Table "uniqueName" Overflow': 'Dépassement Adobe CoolType SING Table "uniqueName"',
    'Adobe Flash Player "newfunction" Invalid Pointer Use': 'Utilisation de pointeur invalide Adobe Flash Player "newfunction"',
    'Adobe Collab.collectEmailInfo Buffer Overflow': 'Dépassement de tampon Adobe Collab.collectEmailInfo',
    'Adobe Collab.getIcon Buffer Overflow': 'Dépassement de tampon Adobe Collab.getIcon',
    'Adobe JBIG2Decode Memory Corruption Exploit': 'Exploit de corruption mémoire Adobe JBIG2Decode',
    'Adobe PDF Embedded EXE Social Engineering': 'Ingénierie sociale par EXE intégré dans un PDF Adobe',
    'Adobe util.printf() Buffer Overflow': 'Dépassement de tampon Adobe util.printf()',
    'Custom EXE to VBA (sent via RAR) (RAR required)': 'EXE personnalisé vers VBA (envoyé via RAR) (RAR requis)',
    'Adobe U3D CLODProgressiveMeshDeclaration Array Overrun': 'Dépassement de tableau Adobe U3D CLODProgressiveMeshDeclaration',
    'Adobe PDF Embedded EXE Social Engineering (NOJS)': 'Ingénierie sociale par EXE intégré dans un PDF Adobe (NOJS)',
    'Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow': 'Dépassement de pile sur le titre de Foxit PDF Reader v4.1.1',
    'Apple QuickTime PICT PnSize Buffer Overflow': 'Dépassement de tampon Apple QuickTime PICT PnSize',
    'Nuance PDF Reader v6.0 Launch Stack Buffer Overflow': 'Dépassement de pile au lancement de Nuance PDF Reader v6.0',
    'Adobe Reader u3D Memory Corruption Vulnerability': 'Vulnérabilité de corruption mémoire Adobe Reader u3D',
    'MSCOMCTL ActiveX Buffer Overflow (ms12-027)\n': 'Dépassement de tampon ActiveX MSCOMCTL (ms12-027)\n',
    'Adobe Flash Player ByteArray Use After Free (2015-07-06)': 'Adobe Flash Player - Use After Free sur ByteArray (2015-07-06)',
    'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow (2015-06-23)': 'Adobe Flash Player - Dépassement de tampon décodage audio Nellymoser (2015-06-23)',
    'Adobe Flash Player Drawing Fill Shader Memory Corruption (2015-05-12)': 'Adobe Flash Player - Corruption mémoire Drawing Fill Shader (2015-05-12)',
    'MS14-012 Microsoft Internet Explorer TextRange Use-After-Free (2014-03-11)': 'MS14-012 Internet Explorer - Use-After-Free sur TextRange (2014-03-11)',
    'MS14-012 Microsoft Internet Explorer CMarkup Use-After-Free (2014-02-13)': 'MS14-012 Internet Explorer - Use-After-Free sur CMarkup (2014-02-13)',
    'Internet Explorer CDisplayPointer Use-After-Free (10/13/2013)': 'Internet Explorer - Use-After-Free sur CDisplayPointer (13/10/2013)',
    'Micorosft Internet Explorer SetMouseCapture Use-After-Free (09/17/2013)': 'Internet Explorer - Use-After-Free sur SetMouseCapture (17/09/2013)',
    'Java Applet JMX Remote Code Execution (UPDATED 2013-01-19)': 'Exécution de code à distance Applet Java JMX (MIS À JOUR 2013-01-19)',
    'Java Applet JMX Remote Code Execution (2013-01-10)': 'Exécution de code à distance Applet Java JMX (2013-01-10)',
    'MS13-009 Microsoft Internet Explorer SLayoutRun Use-AFter-Free (2013-02-13)': 'MS13-009 Internet Explorer - Use-After-Free sur SLayoutRun (2013-02-13)',
    'Microsoft Internet Explorer CDwnBindInfo Object Use-After-Free (2012-12-27)': "Internet Explorer - Use-After-Free sur l'objet CDwnBindInfo (2012-12-27)",
    'Java 7 Applet Remote Code Execution (2012-08-26)': 'Exécution de code à distance Applet Java 7 (2012-08-26)',
    'Microsoft Internet Explorer execCommand Use-After-Free Vulnerability (2012-09-14)': 'Vulnérabilité Use-After-Free Internet Explorer execCommand (2012-09-14)',
    'Java AtomicReferenceArray Type Violation Vulnerability (2012-02-14)': 'Vulnérabilité de violation de type Java AtomicReferenceArray (2012-02-14)',
    'Java Applet Field Bytecode Verifier Cache Remote Code Execution (2012-06-06)': 'Exécution de code à distance via le cache du vérificateur de bytecode Applet Java (2012-06-06)',
    'MS12-037 Internet Explorer Same ID Property Deleted Object Handling Memory Corruption (2012-06-12)': "MS12-037 Internet Explorer - Corruption mémoire sur la gestion d'objet supprimé Same ID Property (2012-06-12)",
    'Microsoft XML Core Services MSXML Uninitialized Memory Corruption (2012-06-12)': 'Corruption mémoire non initialisée Microsoft XML Core Services MSXML (2012-06-12)',
    'Adobe Flash Player Object Type Confusion  (2012-05-04)': 'Confusion de type Adobe Flash Player Object (2012-05-04)',
    'Adobe Flash Player MP4 "cprt" Overflow (2012-02-15)': 'Dépassement Adobe Flash Player MP4 "cprt" (2012-02-15)',
    'MS12-004 midiOutPlayNextPolyEvent Heap Overflow (2012-01-10)': 'MS12-004 Dépassement de tas midiOutPlayNextPolyEvent (2012-01-10)',
    'Java Applet Rhino Script Engine Remote Code Execution (2011-10-18)': 'Exécution de code à distance Applet Java Rhino Script Engine (2011-10-18)',
    'MS11-050 IE mshtml!CObjectElement Use After Free  (2011-06-16)': 'MS11-050 Internet Explorer - Use After Free sur mshtml!CObjectElement (2011-06-16)',
    'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability (2011-04-11)': 'Vulnérabilité de corruption mémoire Adobe Flash Player 10.2.153.1 SWF (2011-04-11)',
    'Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute (2011-06-01)': 'Téléchargement et exécution via la propriété ActiveX URL du client Cisco AnyConnect VPN (2011-06-01)',
    'Internet Explorer CSS Import Use After Free (2010-11-29)': "Internet Explorer - Use After Free sur l'import CSS (2010-11-29)",
    'Microsoft WMI Administration Tools ActiveX Buffer Overflow (2010-12-21)': "Dépassement de tampon ActiveX des outils d'administration Microsoft WMI (2010-12-21)",
    'Internet Explorer CSS Tags Memory Corruption (2010-11-03)': 'Corruption mémoire des balises CSS dans Internet Explorer (2010-11-03)',
    'Sun Java Applet2ClassLoader Remote Code Execution (2011-02-15)': 'Exécution de code à distance Sun Java Applet2ClassLoader (2011-02-15)',
    'Sun Java Runtime New Plugin docbase Buffer Overflow (2010-10-12)': 'Dépassement de tampon docbase du nouveau plugin Sun Java Runtime (2010-10-12)',
    'Microsoft Windows WebDAV Application DLL Hijacker (2010-08-18)': "Détournement de DLL via l'application Microsoft Windows WebDAV (2010-08-18)",
    'Adobe Flash Player AVM Bytecode Verification Vulnerability (2011-03-15)': 'Vulnérabilité de vérification de bytecode AVM Adobe Flash Player (2011-03-15)',
    'Adobe Shockwave rcsL Memory Corruption Exploit (2010-10-21)': 'Exploit de corruption mémoire Adobe Shockwave rcsL (2010-10-21)',
    'Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow (2010-09-07)': 'Dépassement de pile Adobe CoolType SING Table "uniqueName" (2010-09-07)',
    'Apple QuickTime 7.6.7 Marshaled_pUnk Code Execution (2010-08-30)': 'Exécution de code Apple QuickTime 7.6.7 Marshaled_pUnk (2010-08-30)',
    'Microsoft Help Center XSS and Command Execution (2010-06-09)': 'XSS et exécution de commandes Microsoft Help Center (2010-06-09)',
    'Microsoft Internet Explorer iepeers.dll Use After Free (2010-03-09)': 'Internet Explorer - Use After Free sur iepeers.dll (2010-03-09)',
    'Microsoft Internet Explorer "Aurora" Memory Corruption (2010-01-14)': 'Corruption mémoire Internet Explorer "Aurora" (2010-01-14)',
    'Microsoft Internet Explorer Tabular Data Control Exploit (2010-03-0)': "Exploit Tabular Data Control d'Internet Explorer (2010-03-0)",
    'Microsoft Internet Explorer 7 Uninitialized Memory Corruption (2009-02-10)': 'Corruption mémoire non initialisée Internet Explorer 7 (2009-02-10)',
    'Microsoft Internet Explorer Style getElementsbyTagName Corruption (2009-11-20)': "Corruption du style getElementsbyTagName d'Internet Explorer (2009-11-20)",
    'Microsoft Internet Explorer isComponentInstalled Overflow (2006-02-24)': "Dépassement isComponentInstalled d'Internet Explorer (2006-02-24)",
    'Microsoft Internet Explorer Data Binding Corruption (2008-12-07)': 'Corruption de liaison de données Internet Explorer (2008-12-07)',
    'Microsoft Internet Explorer Unsafe Scripting Misconfiguration (2010-09-20)': 'Mauvaise configuration de script non sécurisé dans Internet Explorer (2010-09-20)',
    'FireFox 3.5 escape Return Value Memory Corruption (2009-07-13)': 'Corruption mémoire de la valeur de retour escape dans FireFox 3.5 (2009-07-13)',
    'FireFox 3.6.16 mChannel use after free vulnerability (2011-05-10)': 'Vulnérabilité use after free mChannel dans FireFox 3.6.16 (2011-05-10)',
    'Metasploit Browser Autopwn (USE AT OWN RISK!)\n': 'Autopwn navigateur Metasploit (À UTILISER À VOS RISQUES !)\n',
    'Powershell Alphanumeric Shellcode Injector': 'Injecteur de Shellcode alphanumérique PowerShell',
    'Powershell Reverse Shell': 'Shell inversé PowerShell',
    'Powershell Bind Shell': "Shell d'écoute PowerShell",
    'Powershell Dump SAM Database': 'Extraction de la base SAM via PowerShell',
    'shikata_ga_nai': 'shikata_ga_nai',
    'No Encoding': "Pas d'encodage",
    'Multi-Encoder': 'Multi-Encoder',
    'Backdoored Executable\n': 'Exécutable piégé (backdoor)\n',
    'SE Toolkit Interactive Shell    Custom interactive reverse toolkit designed for SET': 'Shell interactif SE Toolkit    Shell interactif inversé personnalisé conçu pour SET',
    'SE Toolkit HTTP Reverse Shell   Purely native HTTP shell with AES encryption support': 'Shell inversé HTTP SE Toolkit   Shell HTTP purement natif avec support du chiffrement AES',
    'RATTE HTTP Tunneling Payload    Security bypass payload that will tunnel all comms over HTTP\n': 'Payload de tunneling HTTP RATTE   Payload de contournement de sécurité qui tunnelise toute la communication via HTTP\n',
    'Meterpreter Memory Injection (DEFAULT)  This will drop a Meterpreter payload through powershell injection': 'Injection mémoire Meterpreter (PAR DÉFAUT)   Dépose un payload Meterpreter via injection PowerShell',
    'Meterpreter Multi-Memory Injection      This will drop multiple Metasploit payloads via powershell injection': 'Injection mémoire multiple Meterpreter       Dépose plusieurs payloads Metasploit via injection PowerShell',
    'SE Toolkit Interactive Shell            Custom interactive reverse toolkit designed for SET': 'Shell interactif SE Toolkit                  Shell interactif inversé personnalisé conçu pour SET',
    'SE Toolkit HTTP Reverse Shell           Purely native HTTP shell with AES encryption support': 'Shell inversé HTTP SE Toolkit                 Shell HTTP purement natif avec support du chiffrement AES',
    'RATTE HTTP Tunneling Payload            Security bypass payload that will tunnel all comms over HTTP': 'Payload de tunneling HTTP RATTE               Payload de contournement de sécurité qui tunnelise toute la communication via HTTP',
    'ShellCodeExec Alphanum Shellcode        This will drop a meterpreter payload through shellcodeexec': 'Shellcode Alphanumérique ShellCodeExec        Dépose un payload Meterpreter via shellcodeexec',
    'Import your own executable              Specify a path for your own executable': 'Importer votre propre exécutable               Indiquez un chemin vers votre propre exécutable',
    'Import your own commands.txt            Specify payloads to be sent via command line\n': 'Importer votre propre commands.txt              Spécifiez les payloads à envoyer via la ligne de commande\n',
    '\n The {bold}Spearphishing{endc} module allows you to specially craft email messages and send\n them to a large (or small) number of people with attached fileformat malicious\n payloads. If you want to spoof your email address, be sure "Sendmail" is in-\n stalled (apt-get install sendmail) and change the config/set_config SENDMAIL=OFF\n flag to SENDMAIL=ON.\n\n There are two options, one is getting your feet wet and letting SET do\n everything for you (option 1), the second is to create your own FileFormat\n payload and use it in your own attack. Either way, good luck and enjoy!\n': '\n Le module {bold}Spearphishing{endc} vous permet de rédiger des emails sur mesure et de les\n envoyer à un grand (ou petit) nombre de personnes avec des payloads malveillants\n en pièce jointe (FileFormat). Si vous voulez usurper votre adresse email, assurez-vous\n que "Sendmail" est installé (apt-get install sendmail) et changez le paramètre\n config/set_config SENDMAIL=OFF en SENDMAIL=ON.\n\n Il y a deux options : la première consiste à se familiariser et à laisser SET\n tout faire pour vous (option 1), la seconde consiste à créer votre propre\n payload FileFormat et à l\'utiliser dans votre propre attaque. Dans tous les cas,\n bonne chance et amusez-vous bien !\n',
    '\nWelcome to the Social-Engineer Toolkit - {bold}Fast-Track Penetration Testing platform{endc}. These attack vectors\nhave a series of exploits and automation aspects to assist in the art of penetration testing. SET\nnow incorporates the attack vectors leveraged in Fast-Track. All of these attack vectors have been\ncompletely rewritten and customized from scratch as to improve functionality and capabilities.\n': '\nBienvenue dans la plateforme de tests d\'intrusion {bold}Fast-Track{endc} du Social-Engineer Toolkit. Ces vecteurs\nd\'attaque regroupent une série d\'exploits et des aspects d\'automatisation pour vous aider dans l\'art\ndu test d\'intrusion. SET intègre désormais les vecteurs d\'attaque exploités par Fast-Track. Tous ces\nvecteurs d\'attaque ont été entièrement réécrits et personnalisés depuis zéro afin d\'améliorer les\nfonctionnalités et les capacités.\n',
    '\nWelcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing {bold}Exploits Section{endc}. This\nmenu has obscure exploits and ones that are primarily python driven. This will continue to grow over time.\n': '\nBienvenue dans la section {bold}Exploits{endc} de la plateforme de tests d\'intrusion Fast-Track du Social-Engineer Toolkit.\nCe menu regroupe des exploits plus rares et majoritairement écrits en Python. Il continuera de s\'enrichir avec le temps.\n',
    '\nWelcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing {bold}Microsoft SQL Brute Forcer{endc}. This\nattack vector will attempt to identify live MSSQL servers and brute force the weak account passwords that\nmay be found. If that occurs, SET will then compromise the affected system by deploying a binary to\nhexadecimal attack vector which will take a raw binary, convert it to hexadecimal and use a staged approach\nin deploying the hexadecimal form of the binary onto the underlying system. At this point, a trigger will occur\nto convert the payload back to a binary for us.\n': '\nBienvenue dans le {bold}Bruteforceur Microsoft SQL{endc} de la plateforme de tests d\'intrusion Fast-Track du Social-Engineer Toolkit.\nCe vecteur d\'attaque va tenter d\'identifier les serveurs MSSQL actifs et de forcer les mots de passe faibles\nqui pourraient être trouvés. Si cela réussit, SET compromettra alors le système affecté en déployant un\nbinaire via un vecteur d\'attaque binaire vers hexadécimal, qui convertit un binaire brut en hexadécimal et\nl\'envoie par étapes sur le système cible. À ce stade, un déclencheur reconvertira le payload en binaire.\n',
    '\nThe Web Attack module is a unique way of utilizing multiple web-based attacks in order to compromise the intended victim.\n\nThe {bold}Java Applet Attack{endc} method will spoof a Java Certificate and deliver a Metasploit-based payload. Uses a customized java applet created by Thomas Werth to deliver the payload.\n\nThe {bold}Metasploit Browser Exploit{endc} method will utilize select Metasploit browser exploits through an iframe and deliver a Metasploit payload.\n\nThe {bold}Credential Harvester{endc} method will utilize web cloning of a web- site that has a username and password field and harvest all the information posted to the website.\n\nThe {bold}TabNabbing{endc} method will wait for a user to move to a different tab, then refresh the page to something different.\n\nThe {bold}Web-Jacking Attack{endc} method was introduced by white_sheep, emgent. This method utilizes iframe replacements to make the highlighted URL link to appear legitimate however when clicked a window pops up then is replaced with the malicious link. You can edit the link replacement settings in the set_config if it\'s too slow/fast.\n\nThe {bold}Multi-Attack{endc} method will add a combination of attacks through the web attack menu. For example, you can utilize the Java Applet, Metasploit Browser, Credential Harvester/Tabnabbing all at once to see which is successful.\n\nThe {bold}HTA Attack{endc} method will allow you to clone a site and perform PowerShell injection through HTA files which can be used for Windows-based PowerShell exploitation through the browser.\n': '\nLe module d\'attaque Web est une méthode unique combinant plusieurs attaques basées sur le web afin de compromettre la victime visée.\n\nL\'{bold}attaque par Applet Java{endc} usurpe un certificat Java et délivre un payload Metasploit. Elle utilise un applet Java personnalisé créé par Thomas Werth pour délivrer le payload.\n\nL\'{bold}exploit navigateur Metasploit{endc} utilise certains exploits de navigateur Metasploit via une iframe et délivre un payload Metasploit.\n\nLe {bold}Credential Harvester{endc} clone un site web possédant un champ nom d\'utilisateur/mot de passe et récupère toutes les informations envoyées au site.\n\nLe {bold}TabNabbing{endc} attend que l\'utilisateur change d\'onglet, puis rafraîchit la page vers autre chose.\n\nL\'{bold}attaque Web-Jacking{endc} a été introduite par white_sheep et emgent. Cette méthode utilise un remplacement par iframe pour faire apparaître le lien d\'URL mis en évidence comme légitime ; cependant, un clic ouvre une fenêtre qui est ensuite remplacée par le lien malveillant. Vous pouvez modifier les paramètres de remplacement de lien dans set_config si c\'est trop lent/rapide.\n\nLe {bold}mode multi-attaques{endc} combine plusieurs attaques via le menu d\'attaque Web. Par exemple, vous pouvez utiliser l\'Applet Java, l\'exploit navigateur Metasploit, le Credential Harvester/Tabnabbing en même temps pour voir lequel fonctionne.\n\nL\'{bold}attaque HTA{endc} vous permet de cloner un site et d\'effectuer une injection PowerShell via des fichiers HTA, utilisable pour l\'exploitation PowerShell sous Windows via le navigateur.\n',
    '\n The {bold}Arduino-Based Attack{endc} Vector utilizes the Arduin-based device to\n program the device. You can leverage the Teensy\'s, which have onboard\n storage and can allow for remote code execution on the physical\n system. Since the devices are registered as USB Keyboard\'s it\n will bypass any autorun disabled or endpoint protection on the\n system.\n\n You will need to purchase the Teensy USB device, it\'s roughly\n $22 dollars. This attack vector will auto generate the code\n needed in order to deploy the payload on the system for you.\n\n This attack vector will create the .pde files necessary to import\n into Arduino (the IDE used for programming the Teensy). The attack\n vectors range from PowerShell based downloaders, wscript attacks,\n and other methods.\n\n For more information on specifications and good tutorials visit:\n\n http://www.irongeek.com/i.php?page=security/programmable-hid-usb-keystroke-dongle\n\n To purchase a Teensy, visit: http://www.pjrc.com/store/teensy.html\n Special thanks to: IronGeek, WinFang, and Garland\n\n This attack vector also attacks X10 based controllers, be sure to be leveraging\n X10 based communication devices in order for this to work.\n\n Select a payload to create the pde file to import into Arduino:\n': '\n Le vecteur d\'attaque {bold}basé sur Arduino{endc} utilise un appareil basé sur Arduino pour\n programmer le dispositif. Vous pouvez tirer parti des Teensy, qui disposent\n d\'un stockage embarqué et permettent l\'exécution de code à distance sur\n le système physique. Comme ces appareils sont reconnus comme des claviers\n USB, ils contournent toute protection par désactivation de l\'autorun ou\n par protection des terminaux.\n\n Vous devrez acheter le dispositif USB Teensy, pour environ 22 dollars.\n Ce vecteur d\'attaque génère automatiquement le code nécessaire pour\n déployer le payload sur le système.\n\n Ce vecteur d\'attaque créera les fichiers .pde nécessaires à importer\n dans Arduino (l\'IDE utilisé pour programmer le Teensy). Les vecteurs\n d\'attaque vont des téléchargeurs basés sur PowerShell aux attaques\n wscript, et d\'autres méthodes.\n\n Pour plus d\'informations sur les spécifications et de bons tutoriels, visitez :\n\n http://www.irongeek.com/i.php?page=security/programmable-hid-usb-keystroke-dongle\n\n Pour acheter un Teensy, visitez : http://www.pjrc.com/store/teensy.html\n Remerciements spéciaux à : IronGeek, WinFang, et Garland\n\n Ce vecteur d\'attaque cible aussi les contrôleurs basés sur X10, assurez-vous\n d\'utiliser des dispositifs de communication X10 pour que cela fonctionne.\n\n Sélectionnez un payload pour créer le fichier pde à importer dans Arduino :\n',
    '\n The {bold}Wireless Attack{endc} module will create an access point leveraging your\n wireless card and redirect all DNS queries to you. The concept is fairly\n simple, SET will create a wireless access point, DHCP server, and spoof\n DNS to redirect traffic to the attacker machine. It will then exit out\n of that menu with everything running as a child process.\n\n You can then launch any SET attack vector you want, for example the Java\n Applet attack and when a victim joins your access point and tries going to\n a website, will be redirected to your attacker machine.\n\n This attack vector requires AirBase-NG, AirMon-NG, DNSSpoof, and dhcpd3.\n\n': '\n Le module d\'{bold}attaque sans fil{endc} crée un point d\'accès en utilisant votre\n carte sans fil et redirige toutes les requêtes DNS vers vous. Le concept est\n assez simple : SET crée un point d\'accès sans fil, un serveur DHCP, et usurpe\n le DNS pour rediriger le trafic vers la machine attaquante. Il quitte ensuite\n ce menu avec tout s\'exécutant en tant que processus enfant.\n\n Vous pouvez alors lancer n\'importe quel vecteur d\'attaque SET, par exemple l\'attaque\n par Applet Java, et lorsqu\'une victime rejoint votre point d\'accès et tente d\'accéder\n à un site web, elle sera redirigée vers votre machine attaquante.\n\n Ce vecteur d\'attaque nécessite AirBase-NG, AirMon-NG, DNSSpoof, et dhcpd3.\n\n',
    '\n The {bold}{green}Infectious {endc}USB/CD/DVD module will create an autorun.inf file and a\n Metasploit payload. When the DVD/USB/CD is inserted, it will automatically\n run if autorun is enabled.{endc}\n\n Pick the attack vector you wish to use: fileformat bugs or a straight executable.\n': '\n Le module {bold}{green}Infectious{endc} USB/CD/DVD crée un fichier autorun.inf et un\n payload Metasploit. Lorsque le DVD/USB/CD est inséré, il s\'exécutera\n automatiquement si l\'autorun est activé.{endc}\n\n Choisissez le vecteur d\'attaque que vous souhaitez utiliser : exploits de type fichier ou exécutable direct.\n',
    '\nThe {bold}Powershell Attack Vector{endc} module allows you to create PowerShell specific attacks. These attacks will allow you to use PowerShell which is available by default in all operating systems Windows Vista and above. PowerShell provides a fruitful landscape for deploying payloads and performing functions that  do not get triggered by preventative technologies.\n': '\nLe module {bold}vecteur d\'attaque PowerShell{endc} vous permet de créer des attaques spécifiques à PowerShell. Ces attaques vous permettent d\'utiliser PowerShell, disponible par défaut sur tous les systèmes Windows Vista et ultérieurs. PowerShell offre un terrain fertile pour déployer des payloads et effectuer des opérations qui ne déclenchent pas les technologies de prévention.\n',
}
