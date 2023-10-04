**IMPORTANT NOTE: This section is still in its early stages of documentation and testing. I strongly suggest checking out Sarah Edwards, who is an industry leader in this space, as she has many excellent resources and this section for the most part is reiterating the hard work she has put in. Other excellent resources include the Mac OS X Forensics Wikis and shared spreadsheet containing Forensics Artifacts.**

-   [Sarah Edwards](https://twitter.com/iamevltwin)
-   [Mac4n6](https://www.mac4n6.com/)
-   [SANS FOR518 Reference Sheet](https://digital-forensics.sans.org/media/FOR518-Reference-Sheet.pdf)
-   [Mac OS X 10.9 Forensics Wiki](https://forensicswiki.org/wiki/Mac_OS_X_10.9_-_Artifacts_Location)
-   [Mac OS X 10.11 Forensics Wiki](https://forensicswiki.org/wiki/Mac_OS_X_10.11_(ElCapitan)_-_Artifacts_Location)
-   [Mac OS X Forensics Artifacts Spreadsheet](https://docs.google.com/spreadsheets/d/1X2Hu0NE2ptdRj023OVWIGp5dqZOw-CfxHLOW_GNGpX8/edit#gid=1317205466)

## Dumping Memory

[OSXPMem](https://github.com/wrmsr/pmem/tree/master/OSXPMem)

[MacPmem](https://github.com/google/rekall/releases/download/1.7.2rc1/rekall-OSX-1.7.2rc1.zip)

```
sudo kextload MacPmem.kext
sudo dd if=/dev/pmem of=memorydump.raw
```

## Live Mac IR / Triage

### System Information

```
date
sw_vers
uname –a
hostname
cat /System/Library/CoreServices/SystemVersion.plist
cat /private/var/log/daily.out
cat /Library/preferences/.Globalpreferences.plist
```

### Network Connections

```
netstat –an
netstat –anf
lsof -i
```

### Routing Table

```
netstat –rn
```

### Network Information

```
arp –an
ndp -an
ifconfig
```

### Open Files

```
lsof
```

### File System Usage

```
sudo fs_usage
sudo fs_usage [process] 
sudo fs_usage -f network
sudo fs_usage pid [PID]
```

### Bash History

```
cat ~/.bash_history
history
```

### User Logins

```
who -a
w
last
```

### Running Processes

```
ps aux
```

### System Profiler

```
system_profiler -xml -detaillevel full > systemprofiler.spx
```

### Persistent Locations

#### [Quick Overview (KnockKnock)](https://www.objective-see.com/products/knockknock.html)

```
./KnockKnock.app/Contents/MacOS/KnockKnock -whosthere > /path/to/some/file.json
```

#### XPC Services

```
ls Applications/<application>.app/Contents/XPCServices/
cat Applications/<application>.app/Contents/XPCServices/*.xpc/Contents/Info.plist
ls ~/System/Library/XPCServices/
```

#### Launch Agents & Launch Daemons

```
ls /Library/LaunchAgents/
ls /System/Library/LaunchAgents/
ls /System/Library/LaunchDaemons/
ls /Library/LaunchDaemons/
ls /users/*/Library/LaunchAgents/
ls /users/*/Library/LaunchDaemons/
```

#### LoginItems

```
cat ~/Library/Preferences/com.apple.loginitems.plist
ls <application>.app/Contents/Library/LoginItems/
```

### Disable Persistent Launch Daemon

```
sudo launchctl unload -w /Library/LaunchDaemons/<name>.plist
sudo launchctl stop /Library/LaunchDaemons/<name>.plist
```

### Web Browsing Preferences

```
cat ~/Library/Preferences/com.apple.Safari.plist 
ls ~/Library/Application Support/Google/Chrome/Default/Preferences
ls ~/Library/Application Support/Firefox/Profiles/********.default/prefs.js
```

### Safari Internet History

```
cat ~/Library/Safari/Downloads.plist
cat ~/Library/Safari/History.plist 
cat ~/Library/Safari/LastSession.plist
ls ~/Library/Caches/com.apple.Safari/Webpage Previews/ 
sqlite3 ~/Library/Caches/com.apple.Safari/Cache.db  
```

### Chrome Internet History

```
ls ~/Library/Application Support/Google/Chrome/Default/History
ls ~/Library/Caches/Google/Chrome/Default/Cache/
ls ~/Library/Caches/Google/Chrome/Default/Media Cache/
```

### Firefox Internet History

```
sqlite3 ~/Library/Application Support/Firefox/Profiles/********.default/places.sqlite 
sqlite3 ~/Library/Application Support/Firefox/Profiles/********.default/downloads.sqlite
sqlite3 ~/Library/Application Support/Firefox/Profiles/********.default/formhistory.sqlite
ls ~/Library/Caches/Firefox/Profiles/********.default/Cache
```

### Apple Email

```
cat ~/Library/Mail/V2/MailData/Accounts.plist
ls ~/Library/Mail/V2/
ls ~/Library/Mail Downloads/
ls ~/Downloads
cat ~/Library/Mail/V2/MailData/OpenAttachments.plist
```

### Temporary / Cached

```
ls /tmp
ls /var/tmp 
ls /Users/<user>/Library/Caches/Java/tmp
ls /Users/<user>/Library/Caches/Java/cache
	/Applications/Utilities/Java Preferences.app
```

### System and Audit Logs

```
ls /private/var/log/asl/
ls /private/var/audit/
cat /private/var/log/appfirewall.log
ls ~/Library/Logs
ls /Library/Application Support/<app> 
ls /Applications/ 
ls /Library/Logs/
```

### Specific Log Analysis

```
bzcat system.log.1.bz2 
system.log.0.bz2 >> system_all.log 
cat system.log >> system_all.log
syslog -f <file>
syslog –T utc –F raw –d /asl
syslog -d /asl
praudit –xn /var/audit/*
sudo log collect
log show
log stream
```

### Files Quarantined

```
ls ~/Library/Preferences/com.apple.LaunchServices.QuarantineEvents.V2
ls ~/Library/Preferences/com.apple.LaunchServices.QuarantineEvents 
```

### User Accounts / Password Shadows

```
ls /private/var/db/dslocal/nodes/Default/users/ 
ls /private/var/db/shadow/<User GUID>
```

### Pluggable Authentication Modules (PAM)

```
cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/
```

### File Fingerprinting/Reversing

```
file <filename>
xxd <filename>
nm -arch x86_64 <filename>
otool -L <filename>
sudo vmmap <pid>
sudo lsof -p <pid>
xattr –xl <file>
```

### Connected Disks and Partitions

```
diskutil list
diskutil info <disk>
diskutil cs
ap list
gpt –r show 
gpt -r show -l
```

### Disk File Image Information

```
hdiutil imageinfo *.dmg
```

### User Keychain Information

```
security list-keychains
security dump-keychains -d <keychain>
```

### Spotlight Metadata

```
mdimport –X | -A
mdls <file>
```

### Extract download location from Extended Attribute

Note: This is essentially the ‘ADS’ of the MacOS world.

```
xattr -p com.apple.metadata:kMDItemWhereFroms filename.dmg | xxd -r -p | plutil -p -
```

### Locate historical file names from Extended Attribute

```
xattr -p com.apple.genstore.origdisplayname filename
```

## [SANS FOR518 Reference](https://digital-forensics.sans.org/media/FOR518-Reference-Sheet.pdf)

