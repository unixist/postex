package discovery

// Av houses information regarding detected AV
type Av struct {
	Paths         []string
	Procs         []Process
	KernelModules []LoadedKernelModule
	Name          string
}

// Each AV system implements this interface to expose artifacts of the detected system.
// These functions only yield artifacts that are present/running on the system.
type AVDiscoverer interface {
	// Filesystem paths of binaries
	Paths() []string
	// Running processes
	Procs() []Process
	// Loaded kernel modules
	KernelModules() []LoadedKernelModule
	// Name of the AV system
	Name() string
}

type TripwireAV struct {
	AVDiscoverer
}

type OSSECAV struct {
	AVDiscoverer
}

type SophosAV struct {
	AVDiscoverer
}

type SamhainAV struct {
	AVDiscoverer
}

func (t TripwireAV) Paths() []string {
	return existingPaths([]string{
		"/etc/tripwire",
		"/usr/sbin/tripwire",
		"/var/lib/tripwire",
	})
}

func (t TripwireAV) Procs() []Process {
	return []Process{}
}

// KernelModules returns an empty list as Tripwire doesn't use kernel modules.
func (t TripwireAV) KernelModules() []LoadedKernelModule {
	return []LoadedKernelModule{}
}

func (t TripwireAV) Name() string {
	return "Tripwire"
}

func (o OSSECAV) Paths() []string {
	return existingPaths([]string{
		"/var/ossec",
	})
}

func (o OSSECAV) Procs() []Process {
	return runningProcs([]string{
		"ossec-agentd",
		"ossec-syscheckd",
	})
}

// KernelModules returns an empty list as OSSEC doesn't use kernel modules.
func (o OSSECAV) KernelModules() []LoadedKernelModule {
	return []LoadedKernelModule{}
}

func (o OSSECAV) Name() string {
	return "OSSEC"
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

func (s SophosAV) Procs() []Process {
	return runningProcs([]string{
		"savd",
		"savscand",
	})
}

func (o SophosAV) KernelModules() []LoadedKernelModule {
	return []LoadedKernelModule{}
}

func (o SophosAV) Name() string {
	return "Sophos"
}

// Samhain paths and running processes are only detected if Samhain
// wasn't compiled and run with stealth mode enabled.
func (s SamhainAV) Paths() []string {
	return existingPaths([]string{
		"/etc/samhainrc",
		"/run/samhain.pid",
		"/var/lib/samhain",
		"/var/log/samhain_log",
		"/usr/local/sbin/*_stealth",
	})
}

func (s SamhainAV) Procs() []Process {
	return runningProcs([]string{
		"samhain",
	})
}

func (o SamhainAV) KernelModules() []LoadedKernelModule {
	return []LoadedKernelModule{}
}

func (s SamhainAV) Name() string {
	return "Samhain"
}
