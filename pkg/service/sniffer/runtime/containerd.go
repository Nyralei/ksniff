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

	// The cleanup script must tolerate two timing windows:
	//   (1) the sniffer goroutine never reached `ctr run` (e.g. wireshark died
	//       during `crictl pull`) — there is nothing to kill, no-op cleanly;
	//   (2) `ctr run` registered the container/task with containerd just
	//       before (or just after) cleanup fires — we must wait for it to
	//       appear and then kill it, otherwise the tcpdump task is orphaned
	//       under containerd-shim on the host once this privileged pod dies.
	// We poll briefly for the container name to show up, then kill+rm. If it
	// never appears, the loop times out and cleanup ends without doing harm.
	cleanupScript := fmt.Sprintf(`
    set +e
    export CONTAINERD_SOCKET="%s"
    export CONTAINERD_NAMESPACE="k8s.io"
    export CONTAINER_ID="%s"
    CTR="chroot /host ctr -a ${CONTAINERD_SOCKET}"

    found=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if ${CTR} container ls -q 2>/dev/null | grep -qx "${CONTAINER_ID}"; then
            found=1
            break
        fi
        sleep 1
    done

    if [ "${found}" = "1" ]; then
        ${CTR} task kill -s SIGKILL "${CONTAINER_ID}" >/dev/null 2>&1
        for i in 1 2 3 4 5; do
            if ! ${CTR} task ls 2>/dev/null | awk '{print $1}' | grep -qx "${CONTAINER_ID}"; then
                break
            fi
            sleep 1
        done
        ${CTR} task rm --force "${CONTAINER_ID}" >/dev/null 2>&1
        ${CTR} container rm "${CONTAINER_ID}" >/dev/null 2>&1
    fi
    exit 0
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
	return DefaultTCPDumpImage
}
