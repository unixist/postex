Linux postexploitation tool for discovery, backdooring, and lateral movement.

## goals
* run independently of the host environment (no dependence on existing executable utilities, e.g. python, ruby, find). Ideal for use in containers.
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


## examples
### discovery
Here's how to use some of the discovery functions. If the system has the 'jq' utility, you can make queries easier and prettier.

#### See what AV the system is running:
```bash
>: go run snappy.go --av  | jq '.[] | select(.Name == "Antivirus")|.Values[].Name'
"OSSEC"
"Sophos"
"Tripwire"
"Samhain"
>:
```

#### See who's logged into the system and scope the JSON:
```bash
>: go run snappy.go --who
```

```json
    [
      {
        "Name": "Who",
        "Values": [
          {
            "User": "neo",
            "Line": ":0",
            "Host": ":0",
            "Pid": 6348,
            "Time": 1467851439
          },
          {
            "User": "wrabbit",
            "Line": "pts/4",
            "Host": ":0",
            "Pid": 31267,
            "Time": 1467853536
          },
          {
            "User": "morph",
            "Line": "pts/15",
            "Host": ":0",
            "Pid": 31267,
            "Time": 1467913627
          }
        ]
      }
    ]
```

#### See what ipv4/ipv6 connections are connecting to destination port 6697:
```bash
>:go run snappy.go --net | jq '.[]|.Values[]|select(.ForeignPort == 6697)'
```

```json
{
  "User": "superman",
  "Name": "Hexchat",
  "Pid": "33097",
  "Exe": "/usr/bin/hexchat",
  "State": "ESTABLISHED",
  "Ip": "192.168.0.99",
  "Port": 59942,
  "ForeignIp": "192.168.0.4",
  "ForeignPort": 6697
}
{
  "User": "superman",
  "Name": "Hexchat",
  "Pid": "33097",
  "Exe": "/usr/bin/hexchat",
  "State": "ESTABLISHED",
  "Ip": "192.168.0.99",
  "Port": 57556,
  "ForeignIp": "192.168.0.4",
  "ForeignPort": 6697
}
```
