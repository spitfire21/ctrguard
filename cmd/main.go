package main

import (
	//"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	//	"github.com/docker/docker/client"
	"github.com/google/martian/log"
	"github.com/mitchellh/go-ps"
)

// Lazy way for me to iterate through docker options
// 0 means no command follows
// 1 means command is expected after option
var dockerOpts map[string]int = map[string]int{
	"--add-host":              1,
	"--annotation":            1,
	"--attach":                1,
	"--blkio-weight":          1,
	"--blkio-weight-device":   1,
	"--cap-add":               1,
	"--cap-drop":              1,
	"--cgroup-parent":         1,
	"--cgroupns":              1,
	"--cidfile":               1,
	"--cpu-period":            1,
	"--cpu-quota":             1,
	"--cpu-rt-period":         1,
	"--cpu-rt-runtime":        1,
	"--cpu-shares":            1,
	"--cpus":                  1,
	"--cpuset-cpus":           1,
	"--cpuset-mems":           1,
	"--device":                1,
	"--device-cgroup-rule":    1,
	"--device-read-bps":       1,
	"--device-read-iops":      1,
	"--device-write-bps":      1,
	"--device-write-iops":     1,
	"--disable-content-trust": 1,
	"--dns":                   1,
	"--dns-opt":               1,
	"--dns-search":            1,
	"--entrypoint":            1,
	"--env":                   1,
	"--env-file":              1,
	"--expose":                1,
	"--group-add":             1,
	"--health-cmd":            1,
	"--health-interval":       1,
	"--health-retries":        1,
	"--health-start-period":   1,
	"--health-timeout":        1,
	"--hostname":              1,
	"--init":                  1,
	"--ip":                    1,
	"--ip6":                   1,
	"--ipc":                   1,
	"--isolation":             1,
	"--kernel-memory":         1,
	"--label":                 1,
	"--label-file":            1,
	"--link":                  1,
	"--link-local-ip":         1,
	"--log-driver":            1,
	"--log-opt":               1,
	"--mac-address":           1,
	"--memory":                1,
	"--memory-reservation":    1,
	"--memory-swap":           1,
	"--memory-swappiness":     1,
	"--mount":                 1,
	"--name":                  1,
	"--network":               1,
	"--network-alias":         1,
	"--oom-kill-disable":      1,
	"--oom-score-adj":         1,
	"--pid":                   1,
	"--pids-limit":            1,
	"--platform":              1,
	"--publish":               1,
	"--pull":                  1,
	"--pull-always":           1,
	"--read-only":             1,
	"--restart":               1,
	"--restart-delay":         1,
	"--restart-on-failure":    1,
	"--rm":                    0,
	"--runtime":               1,
	"--security-opt":          1,
	"--shm-size":              1,
	"--sig-proxy":             1,
	"--stop-signal":           1,
	"--stop-timeout":          1,
	"--storage-opt":           1,
	"--sysctl":                1,
	"--tmpfs":                 1,
	"--timeout":               1,
	"--tty":                   1,
	"--ulimit":                1,
	"--user":                  1,
	"--uts":                   1,
	"--userns":                1,
	"--volume":                1,
	"--volumes-from":          1,
	"--volume-driver":         1,
	"--workdir":               1,
	"-a":                      1,
	"-c":                      1,
	"-d":                      1,
	"e":                       1,
	"-h":                      1,
	"-i":                      0,
	"-it":                     0,
	"-l":                      1,
	"-m":                      1,
	"-p":                      1,
	"-P":                      1,
	"-q":                      1,
	"-t":                      0,
	"-u":                      1,
	"-v":                      1,
	"-w":                      1,
}

var approvedImage = map[string]string{}

// main is the entry point of the program.
//
// No parameters.
// No return types.
func main() {

	go getOpenProcesses()
	select {}
}

func getOpenProcesses() {
	log.Infof("Starting monitoring for open processes")

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Need to pull new list
			// slow.. need to find a more efficient way
			processes, err := ps.Processes()
			if err != nil {
				panic(err)
			}
			checkRunningProcesses(processes)
		}
	}
}
func sendMessageToProcess(proc ps.Process, message string) error {
	// limits OS to linux; need to build an interface for windows
	// Writing to file descriptor for the process sends a message to the process
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/fd/0", proc.Pid()), os.O_WRONLY, 0)
	defer f.Close()

	if err != nil {
		return errors.New("Could not open file descriptor for process to infrom user of termination")
	}
	if _, err := f.WriteString(message + "\n"); err != nil {
		return errors.New("Could not write to file descriptor for process to infrom user of termination")
	}

	return nil
}

// findRunningImage finds the running image based on the argument string.
//
// It takes a string parameter and returns a string.
func findRunningImage(argument string) string {
	words := strings.Split(argument, " ")
	var image_loc int
	option_set := 0
	for _, word := range words {
		if word == "sudo" {
			continue
		}
		if option_set == 1 {
			option_set = 0
			continue
		}
		if strings.Contains(word, "--") && strings.Contains(word, "=") {
			option_set = 0
			continue
		}
		if val, ok := dockerOpts[word]; ok {
			option_set = val
			continue
		}
		if option_set == 0 {
			image_loc++
		}
		if image_loc == 3 {
			return word
		}

	}
	return ""

}

// checkRunningProcesses iterates through the given processes and checks if they are running docker containers without a valid scan.
//
// processes []ps.Process
func checkRunningProcesses(processes []ps.Process) {
	for _, process := range processes {
		arguments, err := GetRunningArgs(process.Executable(), process.Pid())
		if err != nil {
			continue
		}
		//println(process.Executable(), arguments)
		if strings.Contains(arguments, "docker run") {
			image := findRunningImage(arguments)
			if val, ok := approvedImage[image]; ok && val == "Approved" {
				continue
			}
			if imageDecision(image) {
				fmt.Println("ERROR: running container without a valid scan")
				KillProcess(toOSProcess(process))
				err := sendMessageToProcess(process, "ERROR: running container without a valid scan")
				if err != nil {
					log.Errorf("Error sending message to process: %s", err)
				}

			} else {
				// Add to ignore / approved list
				// cache the process to improve performance
				approvedImage[image] = "Approved"
				log.Infof("Approved: %s", image)
			}
		}
	}
}

func imageHash(image string) string {
	return ""
}

func imageDecision(image string) bool {
	if image == "alpine" {
		return false
	}
	return true
}

// toOSProcess converts a ps.Process to an *os.Process.
//
// process ps.Process
// *os.Process
func toOSProcess(process ps.Process) *os.Process {
	return newProcess(process.Pid())
}

// newProcess returns a pointer to a new os.Process.
//
// It takes an integer pid as a parameter and returns a pointer to an os.Process.
func newProcess(pid int) *os.Process {
	process, err := os.FindProcess(pid)
	if err != nil {
		panic(err)
	}
	return process
}

// GetRunningArgs retrieves the running arguments of a process.
//
// Parameters: exe string, pid int
// Returns: string, error
func GetRunningArgs(exe string, pid int) (string, error) {
	// limits OS to linux; need to build an interface for windows
	dir := fmt.Sprintf("/proc/%d/cmdline", pid)
	content, err := os.ReadFile(dir)
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile("\x00")

	arguments := fmt.Sprintf(m.ReplaceAllString(string(content), " "))
	//arguments = strings.Replace(arguments, exe+" ", "", 1)

	return arguments, err
}

// FindProcess finds the process with the given pid.
//
// It takes an integer pid as a parameter and returns a pointer to os.Process and an error.
func FindProcess(pid int) (*os.Process, error) {
	proc, err := os.FindProcess(pid)

	if err != nil {
		panic(err)
	}

	err = proc.Signal(syscall.Signal(0))

	if err != nil {
		panic(err)
	}

	err = proc.Signal(syscall.SIGSTOP)

	return proc, err
}

func KillProcess(proc *os.Process) (*os.Process, error) {
	err := proc.Signal(syscall.SIGKILL)
	return proc, err
}

func StopProcess(proc *os.Process) (*os.Process, error) {
	err := proc.Signal(syscall.SIGSTOP)
	return proc, err
}

func ResumeProcess(proc *os.Process) (*os.Process, error) {
	err := proc.Signal(syscall.SIGCONT)
	return proc, err
}

type ImageScanInfo struct {
	Name            string
	NumOfLayers     int
	NumberOfScanned int
}

type PackageCreator struct {
	Name string
	Org  string
}

type Package struct {
	Name        string
	Version     string
	Arch        string
	Creator     PackageCreator
	DownloadURL string
	HomepageURL string
	License     []string
	Files       []string
	CPEs        []string
}
