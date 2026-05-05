package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
)

type CrioBridge struct {
}

func NewCrioBridge() *CrioBridge {
	return &CrioBridge{}
}

func (c *CrioBridge) NeedsPid() bool {
	return true
}

func (c *CrioBridge) BuildInspectCommand(containerId string) []string {
	return []string{"chroot", "/host", "crictl", "inspect",
		"--output", "json", containerId}
}

func (c *CrioBridge) ExtractPid(inspection string) (*string, error) {
	var result map[string]json.RawMessage

	if err := json.Unmarshal([]byte(inspection), &result); err != nil {
		return nil, err
	}

	var (
		pid float64
		err error
	)

	switch {
	case result["pid"] != nil:
		pid, err = extractPidCrio117(result)
		if err != nil {
			return nil, fmt.Errorf("error getting container PID from CRI-O: %w", err)
		}
	case result["info"] != nil:
		pid, err = extractPidCrio118(result)
		if err != nil {
			return nil, fmt.Errorf("error getting container PID from CRI-O: %w", err)
		}
	default:
		return nil, errors.New("unable to identify CRI-O version")
	}

	ret := fmt.Sprintf("%.0f", pid)
	return &ret, nil
}

func (c *CrioBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string, socketPath string, tcpdumpImage string) []string {
	return []string{"nsenter", "-n", "-t", *pid, "--", "tcpdump", "-i", netInterface, "-U", "-w", "-", filter}
}

func (c *CrioBridge) BuildCleanupCommand() []string {
	return nil
}

func (c *CrioBridge) GetDefaultImage() string {
	return "maintained/tcpdump"
}

func (c *CrioBridge) GetDefaultSocketPath() string {
	return "/var/run/crio/crio.sock"
}

func (c *CrioBridge) GetDefaultTCPImage() string {
	return ""
}

func extractPidCrio117(partial map[string]json.RawMessage) (float64, error) {
	var result float64
	if err := json.Unmarshal(partial["pid"], &result); err != nil {
		return -1, err
	}
	return result, nil
}

func extractPidCrio118(partial map[string]json.RawMessage) (float64, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(partial["info"], &result); err != nil {
		return -1, err
	}
	pid, ok := result["pid"].(float64)
	if !ok {
		return -1, errors.New("pid field missing or not a number")
	}
	return pid, nil
}
