package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"ksniff/pkg/service/sniffer/runtime"
	"ksniff/utils"
)

type KubernetesApiService interface {
	ExecuteCommand(ctx context.Context, podName string, containerName string, command []string, stdOut io.Writer) (int, error)

	CreatePrivilegedPod(nodeName string, containerName string, image string, socketPath string, timeout time.Duration, serviceAccount string) (*corev1.Pod, error)

	DeletePod(podName string) error

	UploadFile(localPath string, remotePath string, podName string, containerName string) error
}

type KubernetesApiServiceImpl struct {
	clientset       kubernetes.Interface
	restConfig      *rest.Config
	targetNamespace string
}

func NewKubernetesApiService(clientset kubernetes.Interface,
	restConfig *rest.Config, targetNamespace string) KubernetesApiService {

	return &KubernetesApiServiceImpl{clientset: clientset,
		restConfig:      restConfig,
		targetNamespace: targetNamespace}
}

func (k *KubernetesApiServiceImpl) ExecuteCommand(ctx context.Context, podName string, containerName string, command []string, stdOut io.Writer) (int, error) {

	slog.Debug("executing command", "command", command, "container", containerName, "pod", podName, "namespace", k.targetNamespace)
	stdErr := new(Writer)

	executeTcpdumpRequest := ExecCommandRequest{
		KubeRequest: KubeRequest{
			Clientset:  k.clientset,
			RestConfig: k.restConfig,
			Namespace:  k.targetNamespace,
			Pod:        podName,
			Container:  containerName,
		},
		Context: ctx,
		Command: command,
		StdErr:  stdErr,
		StdOut:  stdOut,
	}

	exitCode, err := PodExecuteCommand(executeTcpdumpRequest)
	if err != nil {
		slog.Error("failed executing command", "error", err, "command", command, "exitCode", exitCode, "stderr", stdErr.Output)
		return exitCode, err
	}

	slog.Debug("command executed", "command", command, "exitCode", exitCode, "stderr", stdErr.Output)

	return exitCode, err
}

func (k *KubernetesApiServiceImpl) IsSupportedContainerRuntime(nodeName string) (bool, error) {
	node, err := k.clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, v1.GetOptions{})
	if err != nil {
		return false, err
	}
	nodeRuntimeVersion := node.Status.NodeInfo.ContainerRuntimeVersion
	for _, r := range runtime.SupportedContainerRuntimes {
		if strings.HasPrefix(nodeRuntimeVersion, r) {
			return true, nil
		}
	}
	return false, nil
}

func (k *KubernetesApiServiceImpl) CreatePrivilegedPod(nodeName string, containerName string, image string, socketPath string, timeout time.Duration, serviceAccount string) (*corev1.Pod, error) {
	slog.Debug("creating privileged pod on remote node")

	isSupported, err := k.IsSupportedContainerRuntime(nodeName)
	if err != nil {
		return nil, err
	}
	if !isSupported {
		return nil, fmt.Errorf("container runtime on node %s isn't supported; supported runtimes: %v", nodeName, runtime.SupportedContainerRuntimes)
	}

	privileged := true
	pod := &corev1.Pod{
		TypeMeta: v1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: v1.ObjectMeta{
			GenerateName: "ksniff-",
			Namespace:    k.targetNamespace,
			Labels: map[string]string{
				"app":                    "ksniff",
				"app.kubernetes.io/name": "ksniff",
			},
		},
		Spec: corev1.PodSpec{
			NodeName:      nodeName,
			RestartPolicy: corev1.RestartPolicyNever,
			HostPID:       true,
			Containers: []corev1.Container{{
				Name:            containerName,
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
				Command:         []string{"sh", "-c", "sleep 10000000"},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "container-socket", ReadOnly: true, MountPath: socketPath},
					{Name: "host", ReadOnly: false, MountPath: "/host"},
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("0.1"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1"),
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
			}},
			Volumes: []corev1.Volume{
				{
					Name: "host",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
							Type: hostPathType(corev1.HostPathDirectory),
						},
					},
				},
				{
					Name: "container-socket",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: socketPath,
							Type: hostPathType(corev1.HostPathSocket),
						},
					},
				},
			},
		},
	}

	if serviceAccount != "" {
		pod.Spec.ServiceAccountName = serviceAccount
	}

	createdPod, err := k.clientset.CoreV1().Pods(k.targetNamespace).Create(context.TODO(), pod, v1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	slog.Info("pod created", "pod", createdPod.Name, "namespace", createdPod.Namespace)

	verifyRunning := func() bool {
		p, err := k.clientset.CoreV1().Pods(k.targetNamespace).Get(context.TODO(), createdPod.Name, v1.GetOptions{})
		return err == nil && p.Status.Phase == corev1.PodRunning
	}

	slog.Info("waiting for privileged pod to start")

	if !utils.RunWhileFalse(verifyRunning, timeout, 1*time.Second) {
		return nil, fmt.Errorf("privileged pod did not reach Running state within %s", timeout)
	}

	return createdPod, nil
}

func hostPathType(t corev1.HostPathType) *corev1.HostPathType {
	return &t
}

func (k *KubernetesApiServiceImpl) DeletePod(podName string) error {
	var gracePeriod int64 = 30
	return k.clientset.CoreV1().Pods(k.targetNamespace).Delete(context.TODO(), podName, v1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	})
}

func (k *KubernetesApiServiceImpl) checkIfFileExistOnPod(remotePath string, podName string, containerName string) (bool, error) {
	stdOut := new(Writer)
	stdErr := new(Writer)

	command := []string{"/bin/sh", "-c", fmt.Sprintf("test -f %s", remotePath)}

	exitCode, err := k.ExecuteCommand(context.Background(), podName, containerName, command, stdOut)
	if err != nil {
		return false, err
	}

	if exitCode != 0 {
		return false, nil
	}

	if stdErr.Output != "" {
		return false, errors.New("failed to check for tcpdump on remote pod")
	}

	slog.Info("file found on pod", "path", stdOut.Output)

	return true, nil
}

func (k *KubernetesApiServiceImpl) UploadFile(localPath string, remotePath string, podName string, containerName string) error {
	slog.Info("uploading file", "src", localPath, "dst", remotePath, "container", containerName)

	isExist, err := k.checkIfFileExistOnPod(remotePath, podName, containerName)
	if err != nil {
		return err
	}

	if isExist {
		slog.Info("file already present on remote pod")
		return nil
	}

	slog.Info("file not found on remote pod, uploading", "path", remotePath)

	req := UploadFileRequest{
		KubeRequest: KubeRequest{
			Clientset:  k.clientset,
			RestConfig: k.restConfig,
			Namespace:  k.targetNamespace,
			Pod:        podName,
			Container:  containerName,
		},
		Src: localPath,
		Dst: remotePath,
	}

	exitCode, err := PodUploadFile(req)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("upload file failed, exitCode: %d: %w", exitCode, err)
	}

	slog.Info("verifying file uploaded successfully")

	isExist, err = k.checkIfFileExistOnPod(remotePath, podName, containerName)
	if err != nil {
		return err
	}

	if !isExist {
		slog.Error("failed to locate file on pod after upload")
		return errors.New("couldn't locate file on pod after upload")
	}

	slog.Info("file uploaded successfully")

	return nil
}
