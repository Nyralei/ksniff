package sniffer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	v1 "k8s.io/api/core/v1"

	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer/runtime"
)

type PrivilegedPodSnifferService struct {
	settings                *config.KsniffSettings
	privilegedPod           *v1.Pod
	privilegedContainerName string
	targetProcessId         *string
	kubernetesApiService    kube.KubernetesApiService
	runtimeBridge           runtime.ContainerRuntimeBridge
}

func NewPrivilegedPodRemoteSniffingService(options *config.KsniffSettings, service kube.KubernetesApiService, bridge runtime.ContainerRuntimeBridge) SnifferService {
	return &PrivilegedPodSnifferService{settings: options, privilegedContainerName: "ksniff-privileged", kubernetesApiService: service, runtimeBridge: bridge}
}

func (p *PrivilegedPodSnifferService) Setup(ctx context.Context) error {
	slog.Info("creating privileged pod", "node", p.settings.DetectedPodNodeName)

	if p.settings.UseDefaultImage {
		p.settings.Image = p.runtimeBridge.GetDefaultImage()
	}
	if p.settings.UseDefaultTCPDumpImage {
		p.settings.TCPDumpImage = p.runtimeBridge.GetDefaultTCPImage()
	}
	if p.settings.UseDefaultSocketPath {
		p.settings.SocketPath = p.runtimeBridge.GetDefaultSocketPath()
	}

	var err error
	p.privilegedPod, err = p.kubernetesApiService.CreatePrivilegedPod(
		p.settings.DetectedPodNodeName,
		p.privilegedContainerName,
		p.settings.Image,
		p.settings.SocketPath,
		p.settings.UserSpecifiedPodCreateTimeout,
		p.settings.UserSpecifiedServiceAccount,
	)
	if err != nil {
		slog.Error("failed to create privileged pod", "error", err, "node", p.settings.DetectedPodNodeName)
		return err
	}

	slog.Info("privileged pod created", "pod", p.privilegedPod.Name, "node", p.settings.DetectedPodNodeName)

	if p.runtimeBridge.NeedsPid() {
		var buff bytes.Buffer
		command := p.runtimeBridge.BuildInspectCommand(p.settings.DetectedContainerId)
		exitCode, err := p.kubernetesApiService.ExecuteCommand(ctx, p.privilegedPod.Name, p.privilegedContainerName, command, &buff)
		if err != nil {
			slog.Error("failed to inspect container", "error", err, "exitCode", exitCode)
			return err
		}
		p.targetProcessId, err = p.runtimeBridge.ExtractPid(buff.String())
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *PrivilegedPodSnifferService) Cleanup(ctx context.Context) error {
	command := p.runtimeBridge.BuildCleanupCommand()

	if command != nil {
		slog.Info("removing privileged container", "container", p.privilegedContainerName)
		exitCode, err := p.kubernetesApiService.ExecuteCommand(ctx, p.privilegedPod.Name, p.privilegedContainerName, command, &kube.NopWriter{})
		if err != nil {
			slog.Error("failed to remove privileged container; please remove manually",
				"error", err, "container", p.privilegedContainerName, "exitCode", exitCode)
		} else {
			slog.Info("privileged container removed", "container", p.privilegedContainerName)
		}
	}

	if p.privilegedPod != nil {
		slog.Info("removing privileged pod", "pod", p.privilegedPod.Name)
		if err := p.kubernetesApiService.DeletePod(p.privilegedPod.Name); err != nil {
			slog.Error("failed to remove privileged pod", "error", err, "pod", p.privilegedPod.Name)
			return err
		}
		slog.Info("privileged pod removed", "pod", p.privilegedPod.Name)
	}

	return nil
}

func (p *PrivilegedPodSnifferService) Start(ctx context.Context, stdOut io.Writer) error {
	slog.Info("starting remote sniffing using privileged pod")

	command := p.runtimeBridge.BuildTcpdumpCommand(
		&p.settings.DetectedContainerId,
		p.settings.UserSpecifiedInterface,
		p.settings.UserSpecifiedFilter,
		p.targetProcessId,
		p.settings.SocketPath,
		p.settings.TCPDumpImage,
	)

	exitCode, err := p.kubernetesApiService.ExecuteCommand(ctx, p.privilegedPod.Name, p.privilegedContainerName, command, stdOut)
	if err != nil {
		if ctx.Err() != nil {
			return nil // context cancelled — normal shutdown (wireshark closed, pod deleted, SIGINT)
		}
		slog.Error("failed to start sniffing using privileged pod", "error", err, "exitCode", exitCode)
		return err
	}
	if exitCode == 137 || exitCode == 143 {
		// SIGKILL/SIGTERM: helper pod was externally terminated (e.g. kubectl delete pod)
		return nil
	}
	if exitCode != 0 {
		return fmt.Errorf("sniffing command exited with code %d; check that nsenter and tcpdump are present in the helper image", exitCode)
	}

	slog.Info("remote sniffing using privileged pod completed")
	return nil
}
