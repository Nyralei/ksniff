package config

import (
	"time"

	"k8s.io/cli-runtime/pkg/genericclioptions"
)

type KsniffSettings struct {
	UserSpecifiedPodName           string
	UserSpecifiedInterface         string
	UserSpecifiedFilter            string
	UserSpecifiedPodCreateTimeout  time.Duration
	UserSpecifiedContainer         string
	UserSpecifiedNamespace         string
	UserSpecifiedOutputFile        string
	UserSpecifiedLocalTcpdumpPath  string
	UserSpecifiedRemoteTcpdumpPath string
	UserSpecifiedVerboseMode       bool
	Mode                           string
	TCPDumpImage                   string
	UseDefaultTCPDumpImage         bool
	UserSpecifiedKubeContext       string
}

func NewKsniffSettings(streams genericclioptions.IOStreams) *KsniffSettings {
	return &KsniffSettings{}
}
