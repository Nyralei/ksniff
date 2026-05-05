package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"ksniff/pkg/config"
)

func TestComplete_NotEnoughArguments(t *testing.T) {
	// given
	settings := config.NewKsniffSettings()
	sniff := NewKsniff(settings)
	cmd := &cobra.Command{}
	var commands []string

	// when
	err := sniff.Complete(cmd, commands)

	// then
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "not enough arguments"))
}

func TestComplete_EmptyPodName(t *testing.T) {
	// given
	settings := config.NewKsniffSettings()
	sniff := NewKsniff(settings)
	cmd := &cobra.Command{}
	var commands []string

	// when
	err := sniff.Complete(cmd, append(commands, ""))

	// then
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "pod name is empty"))
}

func TestComplete_PodNameSpecified(t *testing.T) {
	// given
	settings := config.NewKsniffSettings()
	sniff := NewKsniff(settings)
	cmd := NewCmdSniff(genericclioptions.IOStreams{})
	var commands []string

	// when
	err := sniff.Complete(cmd, append(commands, "pod-name"))

	// then
	assert.Nil(t, err)
	assert.Equal(t, "pod-name", settings.UserSpecifiedPodName)
}

func TestFindLocalTcpdumpBinaryPath_Found(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "static-tcpdump")
	require.NoError(t, os.WriteFile(binaryPath, []byte("fake"), 0o755))

	settings := config.NewKsniffSettings()
	sniff := NewKsniff(settings)
	sniff.tcpdumpLocalBinaryPathLookupList = []string{binaryPath}

	result, err := sniff.findLocalTcpdumpBinaryPath()

	assert.NoError(t, err)
	assert.Equal(t, binaryPath, result)
}

func TestFindLocalTcpdumpBinaryPath_NotFound(t *testing.T) {
	settings := config.NewKsniffSettings()
	sniff := NewKsniff(settings)
	sniff.tcpdumpLocalBinaryPathLookupList = []string{"/nonexistent/path/static-tcpdump"}

	_, err := sniff.findLocalTcpdumpBinaryPath()

	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "couldn't find static tcpdump binary"))
}

func TestNewKsniff_DefaultsMode(t *testing.T) {
	cmd := NewCmdSniff(genericclioptions.IOStreams{})
	modeFlag := cmd.Flags().Lookup("mode")
	require.NotNil(t, modeFlag)
	assert.Equal(t, "upload", modeFlag.DefValue)
}

func TestNewKsniff_DefaultInterface(t *testing.T) {
	cmd := NewCmdSniff(genericclioptions.IOStreams{})
	ifaceFlag := cmd.Flags().Lookup("interface")
	require.NotNil(t, ifaceFlag)
	assert.Equal(t, "any", ifaceFlag.DefValue)
}
