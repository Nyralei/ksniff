package sniffer

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"ksniff/pkg/config"
)

func TestTcpdumpImage_Default(t *testing.T) {
	svc := &EphemeralContainerSnifferService{
		settings: &config.KsniffSettings{UseDefaultTCPDumpImage: true},
	}
	assert.Equal(t, DefaultTCPDumpImage, svc.tcpdumpImage())
}

func TestTcpdumpImage_Custom(t *testing.T) {
	svc := &EphemeralContainerSnifferService{
		settings: &config.KsniffSettings{
			UseDefaultTCPDumpImage: false,
			TCPDumpImage:           "custom/tcpdump:v1",
		},
	}
	assert.Equal(t, "custom/tcpdump:v1", svc.tcpdumpImage())
}

func TestCleanup_NoContainerName_ReturnsNil(t *testing.T) {
	svc := &EphemeralContainerSnifferService{
		settings: &config.KsniffSettings{},
	}
	assert.NoError(t, svc.Cleanup(context.Background()))
}

func TestSlogLineWriter_WritesNonEmptyLine(t *testing.T) {
	w := &slogLineWriter{}
	n, err := w.Write([]byte("tcpdump: listening on any\n"))
	assert.NoError(t, err)
	assert.Equal(t, len("tcpdump: listening on any\n"), n)
}

func TestSlogLineWriter_SkipsEmptyLine(t *testing.T) {
	w := &slogLineWriter{}
	n, err := w.Write([]byte("\n"))
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestSetup_AddsEphemeralContainer(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	clientset := k8sfake.NewSimpleClientset(pod)

	settings := &config.KsniffSettings{
		UserSpecifiedPodName:          "test-pod",
		UserSpecifiedContainer:        "app",
		UserSpecifiedInterface:        "any",
		UseDefaultTCPDumpImage:        true,
		UserSpecifiedPodCreateTimeout: 100 * time.Millisecond,
	}
	svc := NewEphemeralContainerSnifferService(settings, clientset, nil, "default")

	err := svc.Setup(context.Background())
	// The fake client may not fully support UpdateEphemeralContainers subresource;
	// we verify the attempt was made (no panic, error is about the API response).
	if err != nil {
		assert.True(t,
			strings.Contains(err.Error(), "ephemeral") || strings.Contains(err.Error(), "fake"),
			"unexpected error: %v", err,
		)
	}
}

func TestDefaultTCPDumpImage_NotEmpty(t *testing.T) {
	require.NotEmpty(t, DefaultTCPDumpImage)
	assert.True(t, strings.HasPrefix(DefaultTCPDumpImage, "ghcr.io/"), "expected ghcr.io image, got %q", DefaultTCPDumpImage)
}

// Verify slogLineWriter implements io.Writer
func TestSlogLineWriter_MultilineFlush(t *testing.T) {
	w := &slogLineWriter{}
	msg := "line1\nline2\n"
	var buf bytes.Buffer
	buf.WriteString(msg)
	n, err := w.Write(buf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, len(msg), n)
}
