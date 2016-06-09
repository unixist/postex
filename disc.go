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

	ps "github.com/unixist/go-ps"
)

var (
	// CLI flags
	do_gatt      = flag.Bool("gatt", false, "Get all the things")
	do_container = flag.Bool("container", false, "Detect if we're in a container")
	do_pkeys     = flag.Bool("pkeys", false, "Detect private keys")
	do_av        = flag.Bool("av", false, "Check for signs of A/V services running or present")
	pkeyDirs     = flag.String("pkeyDirs", "/root,/home", "Comma-separated dirs to search for private keys. Requires --pkeyDirs.")
	pkeySleep    = flag.Int("pkeySleep", 0, "Length of time in milliseconds to sleep between examining files. Requires --pkeyDirs.")

	//// Global config
	// AV systems we can detect
	AVSystems = []AVDiscoverer{
		OSSECAV{name: "OSSEC"},
	}
	// AV system processes that indicate presence
	AVSystemProcs = map[string][]string{
		"OSSEC": []string{
			"ossec-agentd",
			"ossec-syscheckd",
		},
	}
)

type privateKey struct {
	path      string
	encrypted bool
}

type process struct {
	pid  int
	name string
}

// AV object holds the AV system name and
type OSSECAV struct {
	AVDiscoverer
	// name of the AV system
	name string
}

type AVDiscoverer interface {
	Paths() []string
	Procs() []process
	Name() string
}

// AVResult holds information about AV systems present and/or running.
type AVResult struct {
	// Name of the detected AV system
	name string
	// filesystem paths of binaries related to the detected system
	paths []string
	// running processes related to the detected system
	procs []string
}

func (o OSSECAV) Paths() []string {
	paths := []string{
		"/var/ossec",
	}
	found := []string{}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}
func (o OSSECAV) Procs() []process {
	return nil
}
func (o OSSECAV) Name() string {
	return o.name
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

func getAV() []AVDiscoverer {
	allAV := []AVDiscoverer{}
	for _, av := range AVSystems {
		allAV = append(allAV, av)
	}
	return allAV
}

// TODO:
// OSSEC process: ossec-agentd,ossec-syscheckd; OR just check for processes starting with "ossec-"?
// Sophos process: sav-scan(?)
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
	if *do_av {
		fmt.Printf("AV:")
		for _, av := range getAV() {
			name, paths, procs := av.Name(), av.Paths(), av.Procs()
			if len(paths) > 0 || len(procs) > 0 {
				fmt.Printf("\n\tname=%s files=%v procs=%v", name, paths, procs)
			}
		}
		fmt.Println("")
	}
}
