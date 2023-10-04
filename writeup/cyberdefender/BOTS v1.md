

ip Po1s0n1vy 
40.80.148.42 


Pour lister toutes les url 
c_ip=192.168.250.70 | stats count by url


Identifier bruteforce

imreallynotbatman.com sourcetype=stream:http http_method=”POST” form_data=*username*passwd*

| rex field=form_data “username=(?<user>\w+)”

| rex field=form_data “passwd=(?<pw>\w+)”

| table _time, user, pw

| sort by _time
