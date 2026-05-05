package main

import (
	"log/slog"
	"os"

	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"ksniff/pkg/cmd"
)

// Version is injected at build time via -ldflags.
var Version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	flags := pflag.NewFlagSet("kubectl-sniff", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := cmd.NewCmdSniff(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	root.Version = Version
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
