package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
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
	do_gatt      = flag.Bool("gatt", false, "Get all the things")
	do_pkeys     = flag.Bool("pkeys", false, "Detect private keys")
	pkeyDirs     = flag.String("pkeyDirs", "/root,/home", "Comma-separated directories to search for private keys. Default is '/root,/home'. Requires --pkeyDirs.")
	pkeySleep    = flag.Int("pkeySleep", 0, "Length of time in milliseconds to sleep between examining files. Requires --pkeyDirs.")
	do_av        = flag.Bool("av", false, "Check for signs of A/V services running or present.")
	do_container = flag.Bool("container", false, "Detect if this system is running in a container.")
	do_net       = flag.Bool("net", false, "Grab IPv4 and IPv6 networking connections.")
	do_watches   = flag.Bool("watches", false, "Grab which files/directories are being watched for modification/access/execution.")
	do_arp       = flag.Bool("arp", false, "Grab ARP table for all devices.")
	do_who       = flag.Bool("who", false, "List who's logged in and from where.")

	// Recon over time
	do_pollNet   = flag.Bool("pollnet", false, "Long poll for networking connections and a) output a summary; or b) output regular connection status. [NOT IMPLEMENTED]")
	do_pollUsers = flag.Bool("pollusers", false, "Long poll for users that log into the system. [NOT IMPLEMENTED]")
)

// Antivirus systems we detect
var (
	AVSystems = []AVDiscoverer{
		OSSECAV{name: "OSSEC"},
		SophosAV{name: "Sophos"},
	}
	AuditdRules = "/etc/audit/audit.rules"
)

type privateKey struct {
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
	user, line, host string
	pid              int32
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
func getPrivateKey(path string) privateKey {
	p := privateKey{}
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
	p = privateKey{
		path:      path,
		encrypted: strings.HasSuffix(line, "ENCRYPTED\n"),
	}
	return p
}

// getSSHKeys looks for readable ssh private keys. Optionally sleep for `sleep`
// milliseconds to evade detection.
func getSSHKeys(dir string, sleep int) []privateKey {
	pkeys := []privateKey{}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if sleep != 0 {
			time.Sleep(time.Duration(sleep) * time.Millisecond)
		}
		if info == nil || !info.Mode().IsRegular() {
			return nil
		}
		pkey := getPrivateKey(path)
		if pkey != (privateKey{}) {
			pkeys = append(pkeys, pkey)
		}
		return nil
	})
	return pkeys
}

// Look at init's cgroup and total process count to guess at whether we're in a
// container
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

func getWho() []who {
	found := []who{}
	utmps, err := utmp.ReadUtmp("/var/run/utmp", utmp.LoginProcess)
	if err != nil {
		return found
	}
	for _, u := range utmps {
		found = append(found, who{
			user: string(u.User[:len(u.User)]),
			host: string(u.Host[:len(u.Host)]),
			line: string(u.Line[:len(u.Line)]),
			pid:  u.Pid,
		})
	}
	return found
}

func getAV() []AVDiscoverer {
	allAV := []AVDiscoverer{}
	for _, av := range AVSystems {
		allAV = append(allAV, av)
	}
	return allAV
}

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

// TODO:
// AV: Sophos process: sav-scan(?)
func main() {
	flag.Parse()
	if *do_gatt || *do_container {
		fmt.Printf("isContainer: %v\n", isContainer())
	}
	if *do_gatt || *do_pkeys {
		fmt.Printf("ssh keys:")
		for _, dir := range strings.Split(*pkeyDirs, ",") {
			for _, pkey := range getSSHKeys(dir, *pkeySleep) {
				fmt.Printf("\n\tfile=%v encrypted=%v", pkey.path, pkey.encrypted)
			}
		}
		fmt.Println("")
	}
	if *do_gatt || *do_av {
		fmt.Printf("AV:")
		for _, av := range AVSystems {
			name, paths, procs, mods := av.Name(), av.Paths(), av.Procs(), av.KernelModules()
			if len(paths) > 0 || len(procs) > 0 {
				fmt.Printf("\n\tname=%s files=%v procs=%v, modules=%v", name, paths, procs, mods)
			}
		}
		fmt.Println("")
	}
	if *do_gatt || *do_net {
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
	if *do_gatt || *do_watches {
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
	if *do_gatt || *do_arp {
		neighs, err := netlink.NeighList(0, 0)
		if err != nil {
			fmt.Println("Error: ", err)
		} else {
			fmt.Printf("ARP table:")
			for _, n := range neighs {
				fmt.Printf("\n\tmac=%s ip=%s", n.HardwareAddr, n.IP)
			}
			fmt.Println("")
		}
	}
	if *do_gatt || *do_who {
		fmt.Printf("Logged in:")
		for _, w := range getWho() {
			fmt.Printf("\n\tuser=%s host=%s line=%s pid=%d", w.user, w.host, w.line, w.pid)
		}
		fmt.Println("")
	}
}
