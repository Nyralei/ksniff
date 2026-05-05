package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer"
	"ksniff/pkg/service/sniffer/runtime"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

var (
	ksniffExample = "kubectl sniff hello-minikube-7c77b68cff-qbvsd -c hello-minikube"
)

const minimumNumberOfArguments = 1
const tcpdumpBinaryName = "static-tcpdump"
const tcpdumpRemotePath = "/tmp/static-tcpdump"

var tcpdumpLocalBinaryPathLookupList []string

type Ksniff struct {
	configFlags      *genericclioptions.ConfigFlags
	resultingContext *api.Context
	clientset        *kubernetes.Clientset
	restConfig       *rest.Config
	rawConfig        api.Config
	settings         *config.KsniffSettings
	snifferService   sniffer.SnifferService
	wireshark        *exec.Cmd
}

func NewKsniff(settings *config.KsniffSettings) *Ksniff {
	return &Ksniff{settings: settings, configFlags: genericclioptions.NewConfigFlags(true)}
}

func NewCmdSniff(streams genericclioptions.IOStreams) *cobra.Command {
	ksniffSettings := config.NewKsniffSettings(streams)

	ksniff := NewKsniff(ksniffSettings)

	cmd := &cobra.Command{
		Use:          "sniff pod [-n namespace] [-c container] [-f filter] [-o output-file] [-l local-tcpdump-path] [-r remote-tcpdump-path]",
		Short:        "Perform network sniffing on a container running in a kubernetes cluster.",
		Example:      ksniffExample,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := ksniff.Complete(c, args); err != nil {
				return err
			}
			if err := ksniff.Validate(); err != nil {
				return err
			}
			if err := ksniff.Run(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedNamespace, "namespace", "n", "", "namespace (optional)")
	_ = viper.BindEnv("namespace", "KUBECTL_PLUGINS_CURRENT_NAMESPACE")
	_ = viper.BindPFlag("namespace", cmd.Flags().Lookup("namespace"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedInterface, "interface", "i", "any", "pod interface to packet capture (optional)")
	_ = viper.BindEnv("interface", "KUBECTL_PLUGINS_LOCAL_FLAG_INTERFACE")
	_ = viper.BindPFlag("interface", cmd.Flags().Lookup("interface"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedContainer, "container", "c", "", "container (optional)")
	_ = viper.BindEnv("container", "KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER")
	_ = viper.BindPFlag("container", cmd.Flags().Lookup("container"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedFilter, "filter", "f", "", "tcpdump filter (optional)")
	_ = viper.BindEnv("filter", "KUBECTL_PLUGINS_LOCAL_FLAG_FILTER")
	_ = viper.BindPFlag("filter", cmd.Flags().Lookup("filter"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedOutputFile, "output-file", "o", "",
		"output file path, tcpdump output will be redirect to this file instead of wireshark (optional) ('-' stdout)")
	_ = viper.BindEnv("output-file", "KUBECTL_PLUGINS_LOCAL_FLAG_OUTPUT_FILE")
	_ = viper.BindPFlag("output-file", cmd.Flags().Lookup("output-file"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedLocalTcpdumpPath, "local-tcpdump-path", "l", "",
		"local static tcpdump binary path (optional)")
	_ = viper.BindEnv("local-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_LOCAL_TCPDUMP_PATH")
	_ = viper.BindPFlag("local-tcpdump-path", cmd.Flags().Lookup("local-tcpdump-path"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedRemoteTcpdumpPath, "remote-tcpdump-path", "r", tcpdumpRemotePath,
		"remote static tcpdump binary path (optional)")
	_ = viper.BindEnv("remote-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_REMOTE_TCPDUMP_PATH")
	_ = viper.BindPFlag("remote-tcpdump-path", cmd.Flags().Lookup("remote-tcpdump-path"))

	cmd.Flags().BoolVarP(&ksniffSettings.UserSpecifiedVerboseMode, "verbose", "v", false,
		"if specified, ksniff output will include debug information (optional)")
	_ = viper.BindEnv("verbose", "KUBECTL_PLUGINS_LOCAL_FLAG_VERBOSE")
	_ = viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))

	cmd.Flags().StringVarP(&ksniffSettings.Mode, "mode", "", "upload",
		"sniffing mode: upload (default), ephemeral, or privileged")
	_ = viper.BindEnv("mode", "KSNIFF_MODE")
	_ = viper.BindPFlag("mode", cmd.Flags().Lookup("mode"))

	cmd.Flags().DurationVarP(&ksniffSettings.UserSpecifiedPodCreateTimeout, "pod-creation-timeout", "",
		1*time.Minute, "the length of time to wait for pod/container to start (e.g. 20s, 2m, 1h). "+
			"A value of zero means it never times out.")

	cmd.Flags().StringVarP(&ksniffSettings.Image, "image", "", "",
		"the privileged container image (optional, privileged mode only)")
	_ = viper.BindEnv("image", "KUBECTL_PLUGINS_LOCAL_FLAG_IMAGE")
	_ = viper.BindPFlag("image", cmd.Flags().Lookup("image"))

	cmd.Flags().StringVarP(&ksniffSettings.TCPDumpImage, "tcpdump-image", "", "",
		"the tcpdump container image (optional)")
	_ = viper.BindEnv("tcpdump-image", "KUBECTL_PLUGINS_LOCAL_FLAG_TCPDUMP_IMAGE")
	_ = viper.BindPFlag("tcpdump-image", cmd.Flags().Lookup("tcpdump-image"))

	cmd.Flags().StringVarP(&ksniffSettings.SocketPath, "socket", "", "",
		"the container runtime socket path (optional, privileged mode only)")
	_ = viper.BindEnv("socket", "KUBECTL_PLUGINS_SOCKET_PATH")
	_ = viper.BindPFlag("socket", cmd.Flags().Lookup("socket"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedServiceAccount, "serviceaccount", "s", "",
		"the privileged container service account (optional, privileged mode only)")
	_ = viper.BindEnv("serviceaccount", "KUBECTL_PLUGINS_LOCAL_FLAG_SERVICE_ACCOUNT")
	_ = viper.BindPFlag("serviceaccount", cmd.Flags().Lookup("serviceaccount"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedKubeContext, "context", "x", "",
		"kubectl context to work on (optional)")
	_ = viper.BindEnv("context", "KUBECTL_PLUGINS_CURRENT_CONTEXT")
	_ = viper.BindPFlag("context", cmd.Flags().Lookup("context"))

	return cmd
}

func (o *Ksniff) Complete(cmd *cobra.Command, args []string) error {

	if len(args) < minimumNumberOfArguments {
		_ = cmd.Usage()
		return errors.New("not enough arguments")
	}

	o.settings.UserSpecifiedPodName = args[0]
	if o.settings.UserSpecifiedPodName == "" {
		return errors.New("pod name is empty; provide a pod name as the first argument")
	}

	o.settings.UserSpecifiedNamespace = viper.GetString("namespace")
	o.settings.UserSpecifiedContainer = viper.GetString("container")
	o.settings.UserSpecifiedInterface = viper.GetString("interface")
	o.settings.UserSpecifiedFilter = viper.GetString("filter")
	o.settings.UserSpecifiedOutputFile = viper.GetString("output-file")
	o.settings.UserSpecifiedLocalTcpdumpPath = viper.GetString("local-tcpdump-path")
	o.settings.UserSpecifiedRemoteTcpdumpPath = viper.GetString("remote-tcpdump-path")
	o.settings.UserSpecifiedVerboseMode = viper.GetBool("verbose")
	o.settings.UserSpecifiedKubeContext = viper.GetString("context")
	o.settings.Image = viper.GetString("image")
	o.settings.TCPDumpImage = viper.GetString("tcpdump-image")
	o.settings.SocketPath = viper.GetString("socket")
	o.settings.UseDefaultImage = !viper.IsSet("image")
	o.settings.UseDefaultTCPDumpImage = !viper.IsSet("tcpdump-image")
	o.settings.UseDefaultSocketPath = !viper.IsSet("socket")
	o.settings.UserSpecifiedServiceAccount = viper.GetString("serviceaccount")

	var err error

	if o.settings.UserSpecifiedVerboseMode {
		log.Info("running in verbose mode")
		log.SetLevel(log.DebugLevel)
	}

	tcpdumpLocalBinaryPathLookupList, err = o.buildTcpdumpBinaryPathLookupList()
	if err != nil {
		return err
	}

	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	var currentContext *api.Context
	var exists bool

	if o.settings.UserSpecifiedKubeContext != "" {
		currentContext, exists = o.rawConfig.Contexts[o.settings.UserSpecifiedKubeContext]
	} else {
		currentContext, exists = o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	}

	if !exists {
		return errors.New("context doesn't exist")
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{
		CurrentContext: o.settings.UserSpecifiedKubeContext,
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	o.restConfig, err = kubeConfig.ClientConfig()
	if err != nil {
		return err
	}

	o.restConfig.Timeout = 30 * time.Second

	o.clientset, err = kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return err
	}

	o.resultingContext = currentContext.DeepCopy()
	if o.settings.UserSpecifiedNamespace != "" {
		o.resultingContext.Namespace = o.settings.UserSpecifiedNamespace
	}

	return nil
}

func (o *Ksniff) buildTcpdumpBinaryPathLookupList() ([]string, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	ksniffBinaryPath, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		return nil, err
	}

	ksniffBinaryDir := filepath.Dir(ksniffBinaryPath)
	ksniffBinaryPath = filepath.Join(ksniffBinaryDir, tcpdumpBinaryName)

	kubeKsniffPluginFolder := filepath.Join(userHomeDir, filepath.FromSlash("/.kube/plugin/sniff/"), tcpdumpBinaryName)

	return append([]string{o.settings.UserSpecifiedLocalTcpdumpPath, ksniffBinaryPath},
		filepath.Join("/usr/local/bin/", tcpdumpBinaryName), kubeKsniffPluginFolder), nil
}

func (o *Ksniff) Validate() error {
	if len(o.rawConfig.CurrentContext) == 0 {
		return errors.New("context doesn't exist")
	}

	if o.resultingContext.Namespace == "" {
		return errors.New("namespace is empty; specify one with -n or set a default namespace in your kubeconfig")
	}

	var err error

	if o.settings.Mode == "upload" {
		o.settings.UserSpecifiedLocalTcpdumpPath, err = findLocalTcpdumpBinaryPath()
		if err != nil {
			return err
		}
		log.Infof("using tcpdump path at: '%s'", o.settings.UserSpecifiedLocalTcpdumpPath)
	}

	pod, err := o.clientset.CoreV1().Pods(o.resultingContext.Namespace).Get(context.TODO(), o.settings.UserSpecifiedPodName, v1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return fmt.Errorf("cannot sniff on a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	log.Debugf("pod '%s' status: '%s'", o.settings.UserSpecifiedPodName, pod.Status.Phase)

	if len(pod.Spec.Containers) < 1 {
		return errors.New("no containers found in the specified pod")
	}

	if o.settings.UserSpecifiedContainer == "" {
		log.Info("no container specified, taking first container we found in pod.")
		o.settings.UserSpecifiedContainer = pod.Spec.Containers[0].Name
		log.Infof("selected container: '%s'", o.settings.UserSpecifiedContainer)
	}

	o.settings.DetectedPodNodeName = pod.Spec.NodeName

	kubernetesApiService := kube.NewKubernetesApiService(o.clientset, o.restConfig, o.resultingContext.Namespace)

	switch o.settings.Mode {
	case "ephemeral":
		log.Info("sniffing method: ephemeral container")
		o.snifferService = sniffer.NewEphemeralContainerSnifferService(o.settings, o.clientset, o.restConfig, o.resultingContext.Namespace)
	case "privileged":
		log.Info("sniffing method: privileged pod")
		if err := o.findContainerId(pod); err != nil {
			return err
		}
		bridge := runtime.NewContainerRuntimeBridge(o.settings.DetectedContainerRuntime)
		o.snifferService = sniffer.NewPrivilegedPodRemoteSniffingService(o.settings, kubernetesApiService, bridge)
	default:
		log.Info("sniffing method: upload static tcpdump")
		o.snifferService = sniffer.NewUploadTcpdumpRemoteSniffingService(o.settings, kubernetesApiService)
	}

	return nil
}

func (o *Ksniff) findContainerId(pod *corev1.Pod) error {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == o.settings.UserSpecifiedContainer {
			parts := strings.SplitN(cs.ContainerID, "://", 2)
			if len(parts) != 2 {
				break
			}
			o.settings.DetectedContainerRuntime = parts[0]
			o.settings.DetectedContainerId = parts[1]
			return nil
		}
	}
	return fmt.Errorf("couldn't find container '%s' in pod '%s'", o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedPodName)
}

func findLocalTcpdumpBinaryPath() (string, error) {
	log.Debugf("searching for tcpdump binary using lookup list: '%v'", tcpdumpLocalBinaryPathLookupList)

	for _, possibleTcpdumpPath := range tcpdumpLocalBinaryPathLookupList {
		if _, err := os.Stat(possibleTcpdumpPath); err == nil {
			log.Debugf("tcpdump binary found at: '%s'", possibleTcpdumpPath)

			return possibleTcpdumpPath, nil
		}

		log.Debugf("tcpdump binary was not found at: '%s'", possibleTcpdumpPath)
	}

	return "", fmt.Errorf("couldn't find static tcpdump binary on any of: '%v'", tcpdumpLocalBinaryPathLookupList)
}

func (o *Ksniff) Run() error {
	log.Infof("sniffing on pod: '%s' [namespace: '%s', container: '%s', filter: '%s', interface: '%s']",
		o.settings.UserSpecifiedPodName, o.resultingContext.Namespace, o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedFilter, o.settings.UserSpecifiedInterface)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := o.snifferService.Setup(); err != nil {
		return err
	}

	// Cleanup runs on every exit path: happy, signal, error, panic.
	// A fresh context is used so SIGINT doesn't abort the cleanup itself.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = cleanupCtx // reserved for future ctx-aware Cleanup
		log.Info("starting sniffer cleanup")
		if err := o.snifferService.Cleanup(); err != nil {
			log.WithError(err).Error("cleanup failed; manual teardown may be required")
		}
	}()

	if o.settings.UserSpecifiedOutputFile != "" {
		log.Infof("output file option specified, storing output in: '%s'", o.settings.UserSpecifiedOutputFile)

		var fileWriter io.Writer
		if o.settings.UserSpecifiedOutputFile == "-" {
			fileWriter = os.Stdout
		} else {
			f, err := os.Create(o.settings.UserSpecifiedOutputFile)
			if err != nil {
				return err
			}
			defer f.Close()
			fileWriter = f
		}

		return o.snifferService.Start(ctx, fileWriter)
	}

	log.Info("spawning wireshark!")

	title := fmt.Sprintf("gui.window_title:%s/%s/%s", o.resultingContext.Namespace, o.settings.UserSpecifiedPodName, o.settings.UserSpecifiedContainer)
	o.wireshark = exec.Command("wireshark", "-k", "-i", "-", "-o", title)

	defer func() {
		if o.wireshark != nil && o.wireshark.Process != nil {
			if err := o.wireshark.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				log.WithError(err).Error("failed to kill wireshark process")
			}
		}
	}()

	stdinWriter, err := o.wireshark.StdinPipe()
	if err != nil {
		return err
	}

	sniffDone := make(chan error, 1)
	go func() {
		sniffDone <- o.snifferService.Start(ctx, stdinWriter)
	}()

	wiresharkDone := make(chan error, 1)
	go func() {
		wiresharkDone <- o.wireshark.Run()
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-sniffDone:
		if err != nil {
			log.WithError(err).Error("sniffing stopped unexpectedly")
		}
		return err
	case err := <-wiresharkDone:
		return err
	}
}
