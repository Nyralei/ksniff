package sniffer

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"ksniff/kube"
	"ksniff/pkg/config"
)

type StaticTcpdumpSnifferService struct {
	settings             *config.KsniffSettings
	kubernetesApiService kube.KubernetesApiService
}

func NewUploadTcpdumpRemoteSniffingService(options *config.KsniffSettings, service kube.KubernetesApiService) SnifferService {
	return &StaticTcpdumpSnifferService{settings: options, kubernetesApiService: service}
}

func (u *StaticTcpdumpSnifferService) Setup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	slog.Info("uploading static tcpdump binary", "src", u.settings.UserSpecifiedLocalTcpdumpPath, "dst", u.settings.UserSpecifiedRemoteTcpdumpPath)

	err := u.kubernetesApiService.UploadFile(u.settings.UserSpecifiedLocalTcpdumpPath,
		u.settings.UserSpecifiedRemoteTcpdumpPath, u.settings.UserSpecifiedPodName, u.settings.UserSpecifiedContainer)

	if err != nil {
		slog.Error("failed uploading static tcpdump binary; verify the container has tar installed", "error", err)
		return err
	}

	slog.Info("tcpdump uploaded successfully")

	return nil
}

func (u *StaticTcpdumpSnifferService) Cleanup(_ context.Context) error {
	return nil
}

func (u *StaticTcpdumpSnifferService) Start(ctx context.Context, stdOut io.Writer) error {
	slog.Info("starting sniffing on remote container")

	command := []string{u.settings.UserSpecifiedRemoteTcpdumpPath, "-i", u.settings.UserSpecifiedInterface,
		"-U", "-w", "-", u.settings.UserSpecifiedFilter}

	exitCode, err := u.kubernetesApiService.ExecuteCommand(ctx, u.settings.UserSpecifiedPodName, u.settings.UserSpecifiedContainer, command, stdOut)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("executing sniffer failed, exit code: '%d'", exitCode)
	}

	slog.Info("done sniffing on remote container")

	return nil
}
