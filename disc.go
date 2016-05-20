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
	do_gatt      = flag.Bool("gatt", false, "Get all the things")
	do_container = flag.Bool("container", false, "Detect if we're in a container")
	do_pkeys     = flag.Bool("pkeys", false, "Detect private keys")
	pkeyDirs     = flag.String("keyDirs", "/root,/home", "Comma-separated dirs to search for private keys")
)

type privateKey struct {
	path      string
	encrypted bool
}

func getPrivateKey(path string) privateKey {
	p := privateKey{}
	f, err := os.Open(path)
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

// sshKeys looks for readable ssh private keys. Optionally sleep for `sleep`
// milliseconds to evade detection.
func sshKeys(dir string, sleep int) []privateKey {
	pkeys := []privateKey{}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info == nil || info.IsDir() {
			return nil
		}
		pkey := getPrivateKey(path)
		if pkey != (privateKey{}) {
			pkeys = append(pkeys, pkey)
		}
		return nil
	})
	if sleep != 0 {
		time.Sleep(time.Duration(sleep) * time.Millisecond)
	}
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
func main() {
	flag.Parse()
	if *do_gatt || *do_container {
		fmt.Printf("isContainer: %v\n", isContainer())
	}
	if *do_gatt || *do_pkeys {
		fmt.Printf("ssh keys:\n")
		for _, dir := range strings.Split(*pkeyDirs, ",") {
			for _, pkey := range sshKeys(dir, 0) {
				fmt.Printf("\tfile=%v encrypted=%v\n", pkey.path, pkey.encrypted)
			}
		}
	}
}
