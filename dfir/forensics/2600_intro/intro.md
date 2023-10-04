
## QUELLES DONNÉES ANALYSER ?

L’activité numérique crée de nombreuses traces:  
- Sur l’appareil utilisé  
- Par l’application, le système d’exploitation,  
les « middleware », le système de fichiers...  
- Sur le réseau  
- L’accès GSM/3G/LTE, le Proxy, le NAT, le Firewall...  
- Sur le serveur distant  
- Serveur de publicité, le serveur de login, le serveur de données statique (images), données dynamiques.


## OBJECTIFS DE L’INFORENSIQUE

Reconstituer une scène de crime numérique  
- Victime (gère un site Web)  
Déterminer comment un site Web a été attaqué, le parcours de l’attaquant, quelles données ont fuitées  
- Attaquant  
Prouver que la machine du suspect est celle qui a été utilisée et de quelle manière  
Corréler les données et dates des 2 ensembles de données ci-dessus  
Corréler les événements entre plusieurs sources techniques: le système de fichier, les journaux systèmes, les journaux applicatifs, le journal AV, les journaux proxy et FW


## PRINCIPES FONDAMENTAUX

Préservation des preuves  
- Tracer les intervenants, les dates, la pose et l’examen des sceaux numériques  
- Ne pas polluer les preuves: toujours travailler sur une copie quand cela est possible  
Pouvoir expliquer et prouver sa démarche  
- Comment une information a été obtenue  
- Démontrer les conclusions obtenues  
- Expliquer les doutes restants  
- Importance d’un rapport de qualité (20 à 30% du temps passé)  
Permettre une contre-expertise  
Confidentialité des résultats


## ETAPES D’UNE INVESTIGATION

1. Identification  
- Détecter/identifier l’événement/crime numérique  
2. Préservation  
- Préserver la chaîne de preuve  
3. Collection  
- Récupérer les données et les preuves  
4. Filtrage, Triage et pré-analyse des données  
5. Analyse des preuves  
6. Présentation des résultats (rapport d’analyse)


## TYPES DE COLLECTE

### Live  
- En utilisant la machine elle-même  
- Peut être perturbé par un rootkit (qui cache des fichiers ou processus au système et donc l’outil de collecte!)  
- Exemples de collecte Live:  
- Dump mémoire (y compris les malware décompressés en mémoire)  
- Liste des sessions ouvertes, des processus en cours, des fichiers ouverts, des connections réseaux, avec un  EDR...  
- Dump Registre, Journaux et MFT (métadonnées NTFS)  
- Copies d’écrans  

### Offline  
- Disque, copie intégrale.  
- Pas d’interférence avec le système potentiellement infecté


## METADONNÉES DISQUE (NTFS)
### NIVEAUX D’ABSTRACTION D’UN SYSTÈME  DE FICHIERS

1. Niveau physique (SSD*, HDD, VMDK, VHDX, EWF)  
2. Volume logiques (LVM, option)  
3. Niveau logique: partitions (décrit dans la MBR ou GPT)  
4. Niveau données: cluster/block= Groupe de secteurs  
5. Système de fichiers (NTFS, FAT, EXT4): métadonnées  
6. Fichiers et répertoires  
*https://articles.forensicfocus.com/2016/04/20/ssd-and-emmc-forensics-2016/  
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx


### PRINCIPE DE FONCTIONNEMENT

Au début du niveau N, on a les informations pour gérer le niveau N+1  
- N=0 : au début d’un disque physique (premier secteurs et suivants),  
on a la MBR ou GPT, qui contiennent la table des partitions (utilisée  
par le BIOS ou UEFI)  
- N= 1 ou 2: au début d’une partition, on a les informations pour gérer  
le système de fichiers, des pointeurs vers une table ou un arbre de  
métadonnées  
Une partition NTFS commence avec une VBR, qui contient les  
caractéristiques du système de fichiers et un pointeur vers la MFT  
- http://ntfs.com/ntfs-partition-boot-sector.htm


## FORENSIC À PARTIR D’UNE IMAGE DISQUE

- Image : capture secteur par secteur du niveau « physique », pour ne   rien manquer : SSD, HDD, VMDK, VHDX  
- Accès au logiciel de démarrage : MBR, EFI  
- Accès aux partitions  
- Il faut parfois la clé Bitlocker ou LUKS pour déchiffrer  
- Accès aux partitions ou à l’espace cachés du système  
- Accès aux fichiers effacés (espace libre, mais pas remis à zéro)  
- Format le plus courant : EWF/.E01/Encase  
- https://connect.ed-diamond.com/misc/misc-117/description-du-format-de-stockage-forensique-encase-ewf


### METADONNÉES NTFS

- $MFT : Master File Table  
- Attribut $I30 : index des répertoires  
- $UsnJrnl : journal des données  
- $LogFile : journal des métadonnées  
https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/fsutil-usn  
13cubed: https://www.youtube.com/watch?v=_qElVZJqlGY


## MASTER FILE TABLE

Table des métadonnées NTFS, créée lors de l’initialisation de la partition  
-  ici : 30/11/2021 15h09  
-  Filename : $MFT  
-  Contient une entrée pour elle-même : entrée numéro 0 (zéro)  
-  L’index dans la MFT, c’est la première colonne dans 0-128-6, 0-48-3, 1-128-1, 1-48-2, 10-128-1 ..

### STRUCTURE GÉNÉRALE DE LA MASTER FILE TABLE

- Table  
	- Entrée #0 (MFT)  
		-  Entête « FILE »  
		-  Attributs  
		-  Attributs  
		-  ...  
	-  Entrée #1  
		-  Entête « FILE »  
		-  Attributs  
		-  Attributs  
		-  ...  

https://www.ntfs.com/ntfs-mft.htm


## NTFS: CHAQUE ENTRÉE POSSÈDE DES ATTRIBUTS

	Type Nom Description  
	0x10 $Standard_information Horodatage, flags  
	0x20 $Attribute_List Lorsqu’il y a trop d’attributs pour une seule entrée (1k) de la MFT  
	0x30 $File_Name Répertoire parent, horodatage, taille, flags et nom  
	0x40 $Object_Id Nom du volume, version de NTFS, dirty flag  
	0x50 $Security_Descriptor Info de sécurité et ACLs  
	0x60 $Volume_Name  
	0x70 $Volume_Information Version NTFS et drapeau  
	0x80 $Data Contenu du fichiers  
	0x90 $Index_Root Entête de l’index  
	0xa0 $Index_Allocation Contenu de l’index  
	0xb0 $Bitmap Allocation de l’index  
	0xc0 $Reparse_Point Extensions NTFS. Utilisé pour les soft et hard links, les points de montages.  
	0x100 $Logged_Util_Stream Contenu pour le journal ou les clés de chiffremeny


## ATTRIBUTS NTFS

2 sources d’horodatage:  
• Attribut $STANDARD_INFORMATION (0x10/16)  
• Attribut $FILE_NAME (0x30/48)  

Attribut $DATA (0x80/128)  
0-128-6 : $DATA  
0-48-3 : $FILENAME


## HORODATAGE « MACB »

- M = File Modified  
- A = Accessed  
- C = MFT Modified (Change)  
- B = Created (Birth)

B = date de création du fichier sur ce volume (copie ou installation)  
M = date de modification du contenu (compilation pour un binaire)  
13Cubed : https://www.youtube.com/watch?v=OTea54BelTg


## OUTILLAGE : THE SLEUTH KIT

- Niveau physique (mm pour medium)  
	- mmls disk.e01 ou disk.vmdk : liste les partitions, début et tailles en  
secteurs  
- Niveau partition (f pour filesystem)  
	-  fls : liste les entrées (métadonnées) du système de fichier  
	-  fsstat : stats sur le système de fichier  
	-  Il faut indiquer le début de la partition avec l’option -o  
- Niveau métadonnées (i pour inode)  
	- icat : extrait le contenu d’un fichier  
	- istat : stats sur une entrée (fichier ou répertoire)


## THE SLEUTH KIT : TIMELINE

fls -r -mc -o 2048 > fls_body.txt  
-r : récursif  
-m : mount point (lecteur c dans l’exemple)  
mac_time.pl –b fls_body.txt > fls.txt


## ANALYSE FORENSIQUE SYSTÈME (APERÇU)

- Registre  
- Journaux (evtx, antivirus)  
- Preuves d’exécution : prefetch


## REGISTRE WINDOWS (HIVES)

- Registres système  
	- %SystemRoot%\System32\Config  
		- HKEY_LOCAL_MACHINE (HKLM)  
			- System: (C:\Windows\System32\Config\System)  
			- Software: (C:\Windows\System32\Config\Software)  
			- SAM: (C:\Windows\System32\Config\Sam)  
			- Security: (C:\Windows\System32\Config\Security)  
		- HKEY_CURRENT_CONFIG (HKCC), points to  
			HKLM\SYSTEM\CurrentControlSet\CurrentControlSet\HardwareProfiles\Current  
- Registre Utilisateur, HKEY_CURRENT_USER (HKCU)  
	- Un par profil utilisateur dans %UserProfile%\NTUSER.DAT  
		- C:\Users\laurent\NTUSER.DAT  
	- %userprofile%\AppData\Local\Microsoft\Windows\UsrClass.dat (Vista – Win10)  
	- %userprofile%\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat (XP & 2003)


## UTILISATION DU REGISTRE POUR LE FORENSIC

- Persistence (Run, RunOnce, Autoruns)  
- Preuves d’exécution ou d’ouverture de fichiers (MRU, Most Recently Used, UserAssist)  
- Traces réseau (NetworkList)  
- Traces fichiers (explorateur de fichiers) : ShellBags  
- Marqueurs malware  
- Stockage malware (fileless)  
- Configuration du système, des comptes, des applications...  
... 

Registry Explorer : https://ericzimmerman.github.io/#!index.md


## REGISTRE: OUTILLAGE

- Regripper  
- Ecrit en Perl  
- Syntaxe (Windows) : rip -r hive -p plugin  
- Ruches / hives : system, software, sam, ntuser.dat, usrclass.dat  
- Plugins : shellbags, run, ...  
- https://github.com/keydet89/RegRipper3.0  
- https://hexacorn.com/tools/3r.html


##  JOURNAUX WINDOWS ETVX

Dans c:\windows\system32\winevt\logs  
- system.evtx  
- security.evtx  
- application.evtx  
- powershell.evtx  
- wmi.evtx  
- WindowDefender.evtx  
- RDP.evtx


## JOURNAUX ETVX : OUTILLAGE

- EvtxCmd converti les .etvx en json ou xml  
-f input  
--csvf output.csv  
--csv output_dir  
- https://ericzimmerman.github.io/#!index.md


## PREFETCH (.PF)

C’est une preuve d’exécution  
Disponible par défaut sur les workstations, pas les serveurs.  
Les fichiers prefetch servent à optimiser le chargement des DLL pour les applications Windows en gardant un cache de la liste de ces DLL et en les pré-chargeant. Effet de bord, cela garde des données sur le nombre et l’horodatage des exécutions  
Localisés dans c:\Windows\prefetch  
13cubed : https://www.youtube.com/watch?v=f4RAtR_3zcs


## TRACES APPLICATIVES

Exemple : Navigation Web  
- Historique  
- Download  
- Cookies  
- Cache  
Pour Firefox, Chrome, Edge, Internet Explorer  
Dans les profils utilisateurs

