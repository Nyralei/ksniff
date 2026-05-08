package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
)

// DefaultHelperImage is the privileged-mode helper image (needs crictl, tcpdump, nsenter).
// Override at build time: -ldflags "-X ksniff/pkg/service/sniffer/runtime.DefaultHelperImage=ghcr.io/owner/ksniff-helper:v1.0.0"
var DefaultHelperImage = "ghcr.io/nyralei/ksniff-helper:latest"

type ContainerdBridge struct{}

func NewContainerdBridge() *ContainerdBridge {
	return &ContainerdBridge{}
}

func (d ContainerdBridge) NeedsPid() bool {
	return true
}

func (d ContainerdBridge) BuildInspectCommand(containerId string) []string {
	return []string{"crictl", "--runtime-endpoint", "unix://" + d.GetDefaultSocketPath(),
		"inspect", "--output", "json", containerId}
}

func (d ContainerdBridge) ExtractPid(inspection string) (*string, error) {
	var outer struct {
		Info struct {
			Pid float64 `json:"pid"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(inspection), &outer); err != nil {
		return nil, fmt.Errorf("parse crictl inspect output: %w", err)
	}
	if outer.Info.Pid == 0 {
		return nil, errors.New("pid not found in crictl inspect output")
	}
	ret := fmt.Sprintf("%.0f", outer.Info.Pid)
	return &ret, nil
}

func (d ContainerdBridge) GetDefaultSocketPath() string {
	return "/run/containerd/containerd.sock"
}

func (d ContainerdBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string, socketPath string, tcpdumpImage string) []string {
	return []string{"nsenter", "-n", "-t", *pid, "--", "tcpdump", "-i", netInterface, "-U", "-w", "-", filter}
}

func (d ContainerdBridge) BuildCleanupCommand() []string {
	return nil
}

func (d ContainerdBridge) GetDefaultImage() string {
	return DefaultHelperImage
}

func (d ContainerdBridge) GetDefaultTCPImage() string {
	return DefaultTCPDumpImage
}
