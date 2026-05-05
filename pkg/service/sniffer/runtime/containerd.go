package runtime

import (
	"fmt"

	"ksniff/utils"
)

// DefaultHelperImage is the privileged-mode helper image (needs crictl + jq).
// Override at build time: -ldflags "-X ksniff/pkg/service/sniffer/runtime.DefaultHelperImage=ghcr.io/owner/ksniff-helper:v1.0.0"
var DefaultHelperImage = "ghcr.io/nyralei/ksniff-helper:latest"

type ContainerdBridge struct {
	cleanupCommand []string
}

func NewContainerdBridge() *ContainerdBridge {
	return &ContainerdBridge{}
}

func (d ContainerdBridge) NeedsPid() bool {
	return false
}

func (d ContainerdBridge) BuildInspectCommand(string) []string {
	panic("Containerd doesn't need this implemented")
}

func (d ContainerdBridge) ExtractPid(inspection string) (*string, error) {
	panic("Containerd doesn't need this implemented")
}

func (d ContainerdBridge) GetDefaultSocketPath() string {
	return "/run/containerd/containerd.sock"
}

func (d *ContainerdBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string, socketPath string, tcpdumpImage string) []string {
	containerName := "ksniff-container-" + utils.GenerateRandomString(8)
	tcpdumpCommand := fmt.Sprintf("tcpdump -i %s -U -w - %s", netInterface, filter)
	shellScript := fmt.Sprintf(`
    set -ex
    export CONTAINERD_SOCKET="%s"
    export CONTAINERD_NAMESPACE="k8s.io"
    export CONTAINER_RUNTIME_ENDPOINT="unix:///host${CONTAINERD_SOCKET}"
    export IMAGE_SERVICE_ENDPOINT=${CONTAINER_RUNTIME_ENDPOINT}
    crictl pull %s >/dev/null
    netns=$(crictl inspect %s | jq '.info.runtimeSpec.linux.namespaces[] | select(.type == "network") | .path' | tr -d '"')
    exec chroot /host ctr -a ${CONTAINERD_SOCKET} run --rm --with-ns "network:${netns}" %s %s %s
    `, socketPath, tcpdumpImage, *containerId, tcpdumpImage, containerName, tcpdumpCommand)

	cleanupScript := fmt.Sprintf(`
    set -e
    export CONTAINERD_SOCKET="%s"
    export CONTAINERD_NAMESPACE="k8s.io"
    export CONTAINER_ID="%s"
    chroot /host ctr -a ${CONTAINERD_SOCKET} task kill -s SIGKILL ${CONTAINER_ID} || true
    chroot /host ctr -a ${CONTAINERD_SOCKET} task rm --force ${CONTAINER_ID} || true
    chroot /host ctr -a ${CONTAINERD_SOCKET} container rm ${CONTAINER_ID} || true
    `, socketPath, containerName)
	d.cleanupCommand = []string{"/bin/sh", "-c", cleanupScript}

	return []string{"/bin/sh", "-c", shellScript}
}

func (d *ContainerdBridge) BuildCleanupCommand() []string {
	return d.cleanupCommand
}

func (d ContainerdBridge) GetDefaultImage() string {
	return DefaultHelperImage
}

func (d *ContainerdBridge) GetDefaultTCPImage() string {
	return "docker.io/maintained/tcpdump:latest"
}
