package sniffer

import (
	"context"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/utils"
)

const (
	ephemeralContainerPrefix       = "ksniff-ephem-"
	ephemeralContainerPollInterval = 2 * time.Second
)

type EphemeralContainerSnifferService struct {
	settings               *config.KsniffSettings
	clientset              *kubernetes.Clientset
	restConfig             *rest.Config
	targetNamespace        string
	ephemeralContainerName string
}

func NewEphemeralContainerSnifferService(settings *config.KsniffSettings, clientset *kubernetes.Clientset, restConfig *rest.Config, namespace string) SnifferService {
	return &EphemeralContainerSnifferService{
		settings:        settings,
		clientset:       clientset,
		restConfig:      restConfig,
		targetNamespace: namespace,
	}
}

func (e *EphemeralContainerSnifferService) Setup() error {
	e.ephemeralContainerName = ephemeralContainerPrefix + utils.GenerateRandomString(8)
	log.Infof("adding ephemeral container '%s' to pod '%s'", e.ephemeralContainerName, e.settings.UserSpecifiedPodName)

	pod, err := e.clientset.CoreV1().Pods(e.targetNamespace).Get(context.Background(), e.settings.UserSpecifiedPodName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get pod '%s': %w", e.settings.UserSpecifiedPodName, err)
	}

	privileged := false
	netCapabilities := []corev1.Capability{"NET_ADMIN", "NET_RAW"}
	ephemeralContainer := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:            e.ephemeralContainerName,
			Image:           e.tcpdumpImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"sh", "-c", "sleep 10000000"},
			SecurityContext: &corev1.SecurityContext{
				Privileged: &privileged,
				Capabilities: &corev1.Capabilities{
					Add: netCapabilities,
				},
			},
		},
		TargetContainerName: e.settings.UserSpecifiedContainer,
	}

	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, ephemeralContainer)

	_, err = e.clientset.CoreV1().Pods(e.targetNamespace).UpdateEphemeralContainers(
		context.Background(), e.settings.UserSpecifiedPodName, pod, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to add ephemeral container: %w", err)
	}

	log.Infof("ephemeral container added; waiting for it to start")
	timeout := e.settings.UserSpecifiedPodCreateTimeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	if !utils.RunWhileFalse(e.isEphemeralContainerRunning, timeout, ephemeralContainerPollInterval) {
		return fmt.Errorf("ephemeral container '%s' did not reach Running state within %s", e.ephemeralContainerName, timeout)
	}

	log.Infof("ephemeral container '%s' is running", e.ephemeralContainerName)
	return nil
}

func (e *EphemeralContainerSnifferService) isEphemeralContainerRunning() bool {
	pod, err := e.clientset.CoreV1().Pods(e.targetNamespace).Get(context.Background(), e.settings.UserSpecifiedPodName, v1.GetOptions{})
	if err != nil {
		return false
	}
	for _, s := range pod.Status.EphemeralContainerStatuses {
		if s.Name == e.ephemeralContainerName && s.State.Running != nil {
			return true
		}
	}
	return false
}

func (e *EphemeralContainerSnifferService) Start(ctx context.Context, stdOut io.Writer) error {
	log.Infof("starting tcpdump in ephemeral container '%s'", e.ephemeralContainerName)

	command := []string{"tcpdump", "-i", e.settings.UserSpecifiedInterface, "-U", "-w", "-", e.settings.UserSpecifiedFilter}

	req := kube.ExecCommandRequest{
		KubeRequest: kube.KubeRequest{
			Clientset:  e.clientset,
			RestConfig: e.restConfig,
			Namespace:  e.targetNamespace,
			Pod:        e.settings.UserSpecifiedPodName,
			Container:  e.ephemeralContainerName,
		},
		Context: ctx,
		Command: command,
		StdOut:  stdOut,
		StdErr:  log.StandardLogger().Writer(),
	}

	exitCode, err := kube.PodExecuteCommand(req)
	if err != nil {
		return fmt.Errorf("tcpdump exited with code %d: %w", exitCode, err)
	}
	return nil
}

func (e *EphemeralContainerSnifferService) Cleanup() error {
	if e.ephemeralContainerName == "" {
		return nil
	}
	// Ephemeral containers cannot be removed from a pod's spec, but killing all
	// processes inside causes the kubelet to mark the container as Terminated,
	// leaving the pod otherwise unaffected.
	log.Infof("terminating ephemeral container '%s' (best-effort)", e.ephemeralContainerName)
	req := kube.ExecCommandRequest{
		KubeRequest: kube.KubeRequest{
			Clientset:  e.clientset,
			RestConfig: e.restConfig,
			Namespace:  e.targetNamespace,
			Pod:        e.settings.UserSpecifiedPodName,
			Container:  e.ephemeralContainerName,
		},
		Command: []string{"kill", "-TERM", "1"},
		StdErr:  log.StandardLogger().Writer(),
	}
	_, _ = kube.PodExecuteCommand(req)
	return nil
}

func (e *EphemeralContainerSnifferService) tcpdumpImage() string {
	if !e.settings.UseDefaultTCPDumpImage {
		return e.settings.TCPDumpImage
	}
	return "ghcr.io/nyralei/ksniff-tcpdump:latest"
}
