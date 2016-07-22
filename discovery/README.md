Linux postexploitation tool for discovery, backdooring, and lateral movement.

##goals
* run independently of the host environment (no dependence on existing executable utilities, e.g. python, ruby, find)
* run with minimal liklihood of detection (no execution of potentially detectable commands, e.g. netstat, lsof, who)
* run fast (parallelized native code)

## discovery
* grab a snapshot of host activity like processes, net connections, arp cache, logged in users, more
* ... do the above over a period of time to get a sense of how the machine is used and by whom
* detect security controls: A/V & auditd rules
* grab ssh keys
* serialize discovery data as JSON for easy consumption later 

## backdoor
* modify user's ssh config to force user to enable connection sharing (ControlMaster) when ssh'ing to remote hosts

## lateral movement
* piggy back on forwarded ssh credentials (ssh-agent reuse)
* piggy back on existing ssh connections that have connection sharing enabled (ssh connection reuse)
