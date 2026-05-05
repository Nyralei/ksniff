package kube

import (
	"context"
	"errors"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type KubernetesApiService interface {
	ExecuteCommand(ctx context.Context, podName string, containerName string, command []string, stdOut io.Writer) (int, error)

	UploadFile(localPath string, remotePath string, podName string, containerName string) error
}

type KubernetesApiServiceImpl struct {
	clientset       *kubernetes.Clientset
	restConfig      *rest.Config
	targetNamespace string
}

func NewKubernetesApiService(clientset *kubernetes.Clientset,
	restConfig *rest.Config, targetNamespace string) KubernetesApiService {

	return &KubernetesApiServiceImpl{clientset: clientset,
		restConfig:      restConfig,
		targetNamespace: targetNamespace}
}

func (k *KubernetesApiServiceImpl) ExecuteCommand(ctx context.Context, podName string, containerName string, command []string, stdOut io.Writer) (int, error) {

	log.Infof("executing command: '%s' on container: '%s', pod: '%s', namespace: '%s'", command, containerName, podName, k.targetNamespace)
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
		log.WithError(err).Errorf("failed executing command: '%s', exitCode: '%d', stdErr: '%s'",
			command, exitCode, stdErr.Output)

		return exitCode, err
	}

	log.Infof("command: '%s' executing successfully exitCode: '%d', stdErr :'%s'", command, exitCode, stdErr.Output)

	return exitCode, err
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

	log.Infof("file found: '%s'", stdOut.Output)

	return true, nil
}

func (k *KubernetesApiServiceImpl) UploadFile(localPath string, remotePath string, podName string, containerName string) error {
	log.Infof("uploading file: '%s' to '%s' on container: '%s'", localPath, remotePath, containerName)

	isExist, err := k.checkIfFileExistOnPod(remotePath, podName, containerName)
	if err != nil {
		return err
	}

	if isExist {
		log.Info("file was already found on remote pod")
		return nil
	}

	log.Infof("file not found on: '%s', starting to upload", remotePath)

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

	log.Info("verifying file uploaded successfully")

	isExist, err = k.checkIfFileExistOnPod(remotePath, podName, containerName)
	if err != nil {
		return err
	}

	if !isExist {
		log.Error("failed to upload file.")
		return errors.New("couldn't locate file on pod after upload")
	}

	log.Info("file uploaded successfully")

	return nil
}
