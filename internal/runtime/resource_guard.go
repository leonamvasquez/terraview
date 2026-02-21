package runtime

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ResourceLimits defines configurable resource constraints.
type ResourceLimits struct {
	MaxMemoryMB    int `yaml:"max_memory_mb"`
	MinFreeMemoryMB int `yaml:"min_free_memory_mb"`
	MaxThreads     int `yaml:"max_threads"`
}

// DefaultResourceLimits returns sensible defaults based on system capacity.
func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		MaxMemoryMB:    4096,
		MinFreeMemoryMB: 1024,
		MaxThreads:     runtime.NumCPU(),
	}
}

// SafeResourceLimits returns conservative limits for safe mode.
func SafeResourceLimits() ResourceLimits {
	threads := runtime.NumCPU() / 2
	if threads < 1 {
		threads = 1
	}
	return ResourceLimits{
		MaxMemoryMB:    2048,
		MinFreeMemoryMB: 1500,
		MaxThreads:     threads,
	}
}

// SystemResources holds current system resource measurements.
type SystemResources struct {
	TotalMemoryMB     int
	AvailableMemoryMB int
	CPUCount          int
	LoadAverage       float64
}

// CheckResources verifies the system has enough resources to run Ollama.
func CheckResources(limits ResourceLimits) (*SystemResources, error) {
	res, err := measureResources()
	if err != nil {
		return nil, fmt.Errorf("failed to measure system resources: %w", err)
	}

	if limits.MinFreeMemoryMB > 0 && res.AvailableMemoryMB < limits.MinFreeMemoryMB {
		return res, fmt.Errorf("insufficient memory: %d MB available, %d MB required (configure llm.ollama.min_free_memory_mb)",
			res.AvailableMemoryMB, limits.MinFreeMemoryMB)
	}

	return res, nil
}

// measureResources detects current system resources (Linux and macOS).
func measureResources() (*SystemResources, error) {
	res := &SystemResources{
		CPUCount: runtime.NumCPU(),
	}

	switch runtime.GOOS {
	case "darwin":
		if err := measureDarwin(res); err != nil {
			return res, err
		}
	case "linux":
		if err := measureLinux(res); err != nil {
			return res, err
		}
	case "windows":
		if err := measureWindows(res); err != nil {
			return res, err
		}
	default:
		return res, fmt.Errorf("unsupported OS for resource measurement: %s", runtime.GOOS)
	}

	return res, nil
}

func measureDarwin(res *SystemResources) error {
	// Total memory via sysctl
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		bytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err == nil {
			res.TotalMemoryMB = int(bytes / 1024 / 1024)
		}
	}

	// Available memory via vm_stat
	out, err = exec.Command("vm_stat").Output()
	if err == nil {
		res.AvailableMemoryMB = parseDarwinFreeMemory(string(out))
	}

	// Load average
	out, err = exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err == nil {
		res.LoadAverage = parseLoadAvg(strings.TrimSpace(string(out)))
	}

	return nil
}

func measureLinux(res *SystemResources) error {
	// /proc/meminfo
	out, err := exec.Command("cat", "/proc/meminfo").Output()
	if err == nil {
		parseLinuxMeminfo(string(out), res)
	}

	// Load average
	out, err = exec.Command("cat", "/proc/loadavg").Output()
	if err == nil {
		res.LoadAverage = parseLoadAvg(strings.TrimSpace(string(out)))
	}

	return nil
}

func measureWindows(res *SystemResources) error {
	// Total and available memory via PowerShell (wmic is deprecated)
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`$os = Get-CimInstance Win32_OperatingSystem; Write-Output "$($os.TotalVisibleMemorySize) $($os.FreePhysicalMemory)"`).Output()
	if err == nil {
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) >= 2 {
			if totalKB, e := strconv.ParseInt(fields[0], 10, 64); e == nil {
				res.TotalMemoryMB = int(totalKB / 1024)
			}
			if freeKB, e := strconv.ParseInt(fields[1], 10, 64); e == nil {
				res.AvailableMemoryMB = int(freeKB / 1024)
			}
		}
	}

	// Windows doesn't have a Unix-style load average; approximate via CPU usage
	out, err = exec.Command("powershell", "-NoProfile", "-Command",
		`(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average`).Output()
	if err == nil {
		if pct, e := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); e == nil {
			// Convert percentage to Unix-style load avg approximation
			res.LoadAverage = pct / 100.0 * float64(res.CPUCount)
		}
	}

	return nil
}

// parseDarwinFreeMemory extracts free + inactive pages from vm_stat output.
func parseDarwinFreeMemory(vmstat string) int {
	var freePages, inactivePages int64
	pageSize := int64(16384) // Apple Silicon default

	for _, line := range strings.Split(vmstat, "\n") {
		if strings.HasPrefix(line, "Mach Virtual Memory Statistics") {
			// Extract page size: "Mach Virtual Memory Statistics: (page size of XXXX bytes)"
			if idx := strings.Index(line, "page size of "); idx != -1 {
				sizeStr := line[idx+13:]
				if endIdx := strings.Index(sizeStr, " "); endIdx != -1 {
					if ps, err := strconv.ParseInt(sizeStr[:endIdx], 10, 64); err == nil {
						pageSize = ps
					}
				}
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."))
		val, err := strconv.ParseInt(valStr, 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "Pages free":
			freePages = val
		case "Pages inactive":
			inactivePages = val
		}
	}

	return int((freePages + inactivePages) * pageSize / 1024 / 1024)
}

// parseLinuxMeminfo extracts memory info from /proc/meminfo.
func parseLinuxMeminfo(meminfo string, res *SystemResources) {
	for _, line := range strings.Split(meminfo, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		val, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}

		switch parts[0] {
		case "MemTotal:":
			res.TotalMemoryMB = int(val / 1024)
		case "MemAvailable:":
			res.AvailableMemoryMB = int(val / 1024)
		}
	}
}

// parseLoadAvg extracts the 1-minute load average.
func parseLoadAvg(s string) float64 {
	// macOS format: "{ 1.23 4.56 7.89 }" or Linux: "1.23 4.56 7.89 1/234 5678"
	s = strings.Trim(s, "{ }")
	fields := strings.Fields(s)
	if len(fields) > 0 {
		val, err := strconv.ParseFloat(fields[0], 64)
		if err == nil {
			return val
		}
	}
	return 0
}
