## Dumping Memory

```
dd if=/dev/kmem of=/root/kmem
dd if=/dev/mem of=/root/mem
```

[LiME](https://github.com/504ensicsLabs/LiME/releases)

```
sudo insmod ./lime.ko "path=./Linmen.mem format=raw"
```

[LinPMem](https://github.com/Velocidex/c-aff4/releases/)

```
./linpmem -o memory.aff4
./linpmem memory.aff4 -e PhysicalMemory -o memory.raw
```

## Taking Image

```
fdisk -l
dd if=/dev/sda1 of=/[outputlocation]
```

## Misc Useful Tools

[FastIR](https://github.com/SekoiaLab/Fastir_Collector_Linux)

```
python ./fastIR_collector_linux.py
```

[LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

```
./linenum.sh
./linenum.sh -t
```

## Live Triage

### System Information

```
date
uname –a
lsb_release -a
hostname
cat /proc/version
lsmod
```

### Account Information

```
cat /etc/passwd
cat /etc/shadow
cat /etc/sudoers
cat /etc/sudoers.d/*
cut -d: -f1 /etc/passwd
getent passwd | cut -d: -f1
compgen -u
```

### Current user

```
whoami
who
```

### Last logged on users

```
last
lastb
cat /var/log/auth.log
```

### Initialisation Files

```
cat /etc/bash.bashrc
cat ~/.bash_profile 
cat ~/.bashrc 
```

### Environment and Startup Programs

```
env
cat /etc/profile
ls /etc/profile.d/
cat /etc/profile.d/*
```

### Scheduled Tasks

```
ls /etc/cron.*
ls /etc/cron.*/*
cat /etc/cron.*/*
cat /etc/crontab
crontab -l
```

### Commands That Can Be Run As Root or User

```
sudo -l
```

### SSH Keys and Authorised Users

```
cat /etc/ssh/sshd_config
```

Note: This specifies where the SSH daemon will look for keys. Generally this will be as below.

```
ls /home/*/.ssh/*
cat /home/*/.ssh/id_rsa.pub
cat /home/*/.ssh/authorized_keys
```

### Sudoers File (who who can run commands as a different user)

```
cat /etc/sudoers
```

### Configuration Information

```
ls /etc/*.d
cat /etc/*.d/*
```

### Network Connections / Socket Stats

```
netstat
netstat -apetul
netstat -plan
netstat -plant
netstat -naote
ss
ss -l
ss -ta
ss -tp
```

### DNS Information for Domain

```
dig www.jaiminton.com a
dig www.jaiminton.com any
dig www.jaiminton.com ns
dig www.jaiminton.com soa
dig www.jaiminton.com hinfo
dig www.jaiminton.com txt
dig +short www.jaiminton.com
```

### IPs Allowed to Perform Domain Transfer

```
cat /etc/bind/named.conf.local
```

### Specify IP To Use For Domain Transfer

```
dig @127.0.0.1 domain.here axfr -b <IP>
```

### IP Table Information

```
ls /etc/iptables
cat /etc/iptables/*.v4
cat /etc/iptables/*.v6
iptables -L
```

### Use IPTables For Filtering

[AndreaFortuna Cheatsheet](https://andreafortuna.org/2019/05/08/iptables-a-simple-cheatsheet/)

### Network Configuration

```
ifconfig -a
```

### Difference Between 2 Files

```
diff <file1> <file2>
```

### Browser Plugin Information

```
ls -la ~/.mozilla/plugins
ls -la /usr/lib/mozilla/plugins
ls -la /usr/lib64/mozilla/plugins
ls -la ~/.config/google-chrome/Default/Extensions/
```

### Kernel Modules and Extensions/

```
ls -la /lib/modules/*/kernel/*
```

### File Permissions

```
-rw-r-x-wt 1 fred fred 0 Aug 10 2019 /home/fred/malware
|[-][-][-]- [---][---]
| |  |  | |   |    |
| |  |  | |   |    *-----------------> 7. Group
| |  |  | |   *----------------------> 6. Owner
| |  |  | *--------------------------> 5. Alternate Access Method
| |  |  *----------------------------> 4. Others Permissions
| |  *-------------------------------> 3. Group Permissions
| *----------------------------------> 2. Owner Permissions
*------------------------------------> 1. File Type
```

[File Permissions in Linux](https://www.guru99.com/file-permissions.html)

### Decode base64 Encoded File

```
base64 -d <filename>
echo <b64stream> | base64 -d
```

### Process Information

```
ps -s
ps -l
ps -o
ps -t
ps -m
ps -a
ps -ax
top
```

### Size Of File (Bytes)

```
wc -c <file>
```

### IP Making Most Requests in Access Log

```
cut -d " " -f 1 access.log | sort | uniq -c | sort -n -k 1,1
```

### Count of Unique IPs in Access Log

```
cut -d " " -f 1 access.log | sort -u | wc -l
```

### Unique User Agents in Access Log

```
awk -F \" '{ print $6 }' access.log | sort -u
```

### Most Requested URLs For POST Request in Access Log

```
awk -F \" '{ print $2 }' access.log | grep "POST" | sort | uniq -c | sort -n -k 1,1
```

### Lines In File

```
wc -l <file>
```

### Search files recursively in directory for keyword

```
grep -H -i -r "password" /
```

### Process Tree

```
ps -auxwf
```

### Open Files and space usage

```
lsof
du
```

### Pluggable Authentication Modules (PAM)

```
cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/
```

### Disk / Partition Information

```
fdisk -l
```

### Fulle Path For Command in environment variables

```
which <softwarename>
```

### [System Calls / Network Traffic](https://bytefreaks.net/gnulinux/how-to-capture-all-network-traffic-of-a-single-process)

```
strace -f -e trace=network -s 10000 <PROCESS WITH ARGUMENTS>;
strace -f -e trace=network -s 10000 -p <PID>;
```

### Strings Present In File

```
strings <filepath>
strings -e b <filepath>
```

Note: Below material with thanks to [Craig Rowland - Sandfly Security](https://blog.apnic.net/2019/10/14/how-to-basic-linux-malware-process-forensics-for-incident-responders/)

### Detailed Process Information

```
ls -al /proc/[PID]
```

**Note:**

-   CWD = Current Working Directory of Malware
-   EXE = Binary location and whether it has been deleted
-   Most Common Timestamp = When process was created

### Recover deleted binary which is currently running

```
cp /proc/[PID]/exe /[destination]/[binaryname]
```

### Capture Binary Data for Review

```
cp /proc/[PID]/ /[destination]/[PID]/
```

### Binary hash information

```
sha1sum /[destination]/[binaryname]
md5sum /[destination]/[binaryname]
```

### Process Command Line Information

```
cat /proc/[PID]/cmdline
cat /proc/[PID]/comm
```

**Note:**

-   Significant differences in the above 2 outputs and the specified binary name under /proc/[PID]/exe can be indicative of malicious software attempting to remain undetected.

### Process Environment Variables (incl user who ran binary)

```
strings /proc/[PID]/environ
cat /proc/[PID]/environ
```

### Process file descriptors/maps (what the process is ‘accessing’ or using)

```
ls -al /proc/[PID]/fd
cat /proc/[PID]/maps
```

### Process stack/status information (may reveal useful elements)

```
cat /proc/[PID]/stack
cat /proc/[PID]/status
```

### Deleted binaries which are still running

```
ls -alr /proc/*/exe 2> /dev/null |  grep deleted
```

### Process Working Directories (including common targeted directories)

```
ls -alr /proc/*/cwd
ls -alr /proc/*/cwd 2> /dev/null | grep tmp
ls -alr /proc/*/cwd 2> /dev/null | grep dev
ls -alr /proc/*/cwd 2> /dev/null | grep var
ls -alr /proc/*/cwd 2> /dev/null | grep home
```

### Using JQ To Analyse JSON

```
cat people.json | jq '.[] | select((.name.first == "Fred") or (.name.last == "John"))'
cat people.json | jq '.[] | select((.name.first == "Fred") or (.name.last == "John"))'|@csv
```

### Hidden Directories and Files

```
find / -type d -name ".*"
```

### Immutable Files and Directories (Often Suspicious)

```
lsattr / -R 2> /dev/null | grep "\----i"
```

### SUID/SGID and Sticky Bit Special Permissions

```
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;
```

### File and Directories with no user/group name

```
find / \( -nouser -o -nogroup \) -exec ls -lg  {} \;
```

### File types in current directory

```
file * -p
```

### Executables on file system

```
find / -type f -exec file -p '{}' \; |  grep ELF
```

### Hidden Executables on file system

```
find / -name ".*" -exec file -p '{}' \; | grep ELF
```

### Files modified within the past day

```
find / -mtime -1
```

### Find files for a particular user

```
find /home/ -user fred -type f
```

### Persistent Areas of Interest

```
/etc/rc.local
/etc/initd
/etc/rc*.d
/etc/modules
/etc/cron*
/var/spool/cron/*
/usr/lib/cron/
/usr/lib/cron/tabs
```

### Audit Logs

```
ls -al /var/log/*
ls -al /var/log/*tmp
utmpdump /var/log/btmp
utmpdump /var/run/utmp
utmpdump /var/log/wtmp
```

### Installed Software Packages

```
ls /usr/bin/
ls /usr/local/bin/
```