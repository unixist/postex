package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"sync"
	"time"

	netstat "github.com/drael/GOnetstat"
	disc "github.com/unixist/postex/discovery"
)

// CLI flags
var (
	// Passive recon
	flag_gatt       = flag.Bool("gatt", false, "Get all the things. This flag only performs one-time read actions, e.g. --av, and --who.")
	flag_pkeys      = flag.Bool("pkeys", false, "Detect private keys")
	flag_pkey_dirs  = flag.String("pkey-dirs", "/root,/home", "Comma-separated directories to search for private keys. Default is '/root,/home'. Requires --pkeys.")
	flag_pkey_sleep = flag.Int("pkey-sleep", 0, "Length of time in milliseconds to sleep between examining files. Requires --flag_pkey_dirs.")
	flag_av         = flag.Bool("av", false, "Check for signs of A/V services running or present.")
	flag_container  = flag.Bool("container", false, "Detect if this system is running in a container. [UNRELIABLE]")
	flag_net        = flag.Bool("net", false, "Grab IPv4 and IPv6 networking connections.")
	flag_watches    = flag.Bool("watches", false, "Grab which files/directories are being watched for modification/access/execution.")
	flag_arp        = flag.Bool("arp", false, "Grab ARP table for all devices.")
	flag_who        = flag.Bool("who", false, "List who's logged in and from where.")
	// Passive recon over time
	flag_poll_net    = flag.Bool("pollnet", false, "Long poll for networking connections and a) output a summary; or b) output regular connection status. [NOT IMPLEMENTED]")
	flag_poll_users  = flag.Bool("pollusers", false, "Long poll for users that log into the system. [NOT IMPLEMENTED]")
	flag_stalk_luser = flag.String("stalk-luser", "", "Wait until a user logs in locally and log it. Use \"*\" to match any user.")

	// Active - backdoor
	flag_ssh_cm    = flag.String("ssh-cm", "", "Set user's $HOME/.ssh/config to include a ControlMaster directive for passwordless piggybacking.")
	flag_rm_ssh_cm = flag.String("rm-ssh-cm", "", "Undo --ssh-cm. If the config file is empty after the undo, it will be removed.")
	// Active - lateral movement
	flag_stalk_ruser     = flag.String("stalk-ruser", "", "Wait until a user logs in locally and attempt to also log into that host.")
	flag_stalk_ruser_cmd = flag.String("stalk-ruser-cmd", "", "Command to execute on remote host after successful login.")

	flag_verbose = flag.Bool("verbose", false, "Print status information")
)

func prettyString(i interface{}) string {
	p, err := json.MarshalIndent(i, "", "  ")
	ret := ""
	if err == nil {
		ret = string(p)
	} else {
		ret = fmt.Sprintf("Error:", err.Error())
	}
	return ret
}

func main() {
	flag.Parse()
	output := []disc.Output{}
	gwg := sync.WaitGroup{}
	gl := sync.Mutex{}

	if *flag_gatt || *flag_container {
		gwg.Add(1)
		go func() {
			if *flag_verbose {
				fmt.Println("Checking whether in a container")
			}
			is := disc.IsContainer()
			var values []interface{} = make([]interface{}, 1)
			values[0] = is

			gl.Lock()
			output = append(output, disc.Output{
				Name:   "In Container",
				Values: values,
			})
			gl.Unlock()
			gwg.Done()
		}()
	}
	if *flag_gatt || *flag_pkeys {
		gwg.Add(1)
		go func() {
			if *flag_verbose {
				fmt.Println("Looking for private keys in %v", *flag_pkey_dirs)
			}
			keys := disc.GetSSHKeys(*flag_pkey_dirs, *flag_pkey_sleep)
			var values []interface{} = make([]interface{}, len(keys))
			for i := range keys {
				values[i] = keys[i]
			}

			gl.Lock()
			output = append(output, disc.Output{
				Name:   "SSH Keys",
				Values: values,
			})
			gl.Unlock()
			gwg.Done()
		}()
	}
	if *flag_gatt || *flag_av {
		gwg.Add(1)
		go func() {
			if *flag_verbose {
				avs := []string{}
				for _, av := range disc.AVSystems {
					avs = append(avs, av.Name())
				}
				fmt.Println("Looking for AV systems: %s", strings.Join(avs, ","))
			}
			avs := disc.GetAV()
			var values []interface{} = make([]interface{}, len(avs))
			for i := range avs {
				values[i] = avs[i]
			}

			gl.Lock()
			output = append(output, disc.Output{
				Name:   "Antivirus",
				Values: values,
			})
			gl.Unlock()
			gwg.Done()
		}()
	}
	if *flag_gatt || *flag_net {
		// Add to the global wait group just once
		gwg.Add(1)
		go func() {
			conns := []netstat.Process{}
			// Create a separate wait group for gathering the separate types of network connections
			nwg := sync.WaitGroup{}
			l := sync.Mutex{}

			nwg.Add(1)
			go func() {
				tcp4 := netstat.Tcp()
				l.Lock()
				for _, conn := range tcp4 {
					if conn.State == "ESTABLISHED" {
						conns = append(conns, conn)
					}
				}
				l.Unlock()
				nwg.Done()
			}()

			nwg.Add(1)
			go func() {
				udp4 := netstat.Udp()
				l.Lock()
				for _, conn := range udp4 {
					if conn.State == "ESTABLISHED" {
						conns = append(conns, conn)
					}
				}
				l.Unlock()
				nwg.Done()
			}()

			nwg.Add(1)
			go func() {
				tcp6 := netstat.Tcp6()
				l.Lock()
				for _, conn := range tcp6 {
					if conn.State == "ESTABLISHED" {
						conns = append(conns, conn)
					}
				}
				l.Unlock()
				nwg.Done()
			}()

			nwg.Add(1)
			go func() {
				udp6 := netstat.Udp6()
				l.Lock()
				for _, conn := range udp6 {
					if conn.State == "ESTABLISHED" {
						conns = append(conns, conn)
					}
				}
				l.Unlock()
				nwg.Done()
			}()

			nwg.Wait()

			var values []interface{} = make([]interface{}, len(conns))
			for i := range conns {
				values[i] = conns[i]
			}

			gl.Lock()
			output = append(output, disc.Output{
				Name:   "Network connections",
				Values: values,
			})
			gl.Unlock()
			gwg.Done()
		}()
	}
	if *flag_gatt || *flag_watches {
		gwg.Add(1)
		go func() {
			watches, err := disc.GetAuditWatches()
			var values []interface{} = make([]interface{}, len(watches))
			if err != nil {
				// Only display the flag if watches were requested explicitly
				// or verbosit was requested.
				if *flag_watches || *flag_verbose {
					fmt.Println("Error checking watches: ", err)
				}
			} else {
				for i := range watches {
					values[i] = watches[i]
				}

				gl.Lock()
				output = append(output, disc.Output{
					Name:   "auditd watches",
					Values: values,
				})
				gl.Unlock()
			}
			gwg.Done()
		}()
	}
	if *flag_gatt || *flag_arp {
		gwg.Add(1)
		go func() {
			arp := disc.GetArp()
			var values []interface{} = make([]interface{}, len(arp))
			for i := range arp {
				values[i] = arp[i]
			}

			gl.Lock()
			output = append(output, disc.Output{
				Name:   "ARP",
				Values: values,
			})
			gl.Unlock()
			gwg.Done()
		}()
	}
	if *flag_gatt || *flag_who {
		gwg.Add(1)
		go func() {
			who := disc.GetWho()
			var values []interface{} = make([]interface{}, len(who))
			for i := range who {
				values[i] = who[i]
			}

			gl.Lock()
			output = append(output, disc.Output{
				Name:   "Who",
				Values: values,
			})
			gl.Unlock()
			gwg.Done()
		}()
	}
	if *flag_stalk_luser != "" {
		disc.StalkLocalLogin(*flag_stalk_luser, func(user string, conn disc.NetConn) error {
			fmt.Printf("User logged in %v: %s@%s\n", time.Now(), user, conn.Src.Ip)
			return nil
		})
	}
	if *flag_stalk_ruser != "" {
		disc.StalkRemoteLogin(*flag_stalk_ruser, disc.AttemptRemoteLogin)
	}
	if *flag_ssh_cm != "" {
		disc.SetSSHControlMaster(*flag_ssh_cm)
	}
	if *flag_rm_ssh_cm != "" {
		disc.UnsetSSHControlMaster(*flag_rm_ssh_cm)
	}

	if *flag_verbose {
		fmt.Println("Waiting for all discoveries to complete")
	}
	gwg.Wait()
	fmt.Println(prettyString(output))
}
