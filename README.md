# ksniff

[![unit-test](https://github.com/Nyralei/ksniff/actions/workflows/unit-test.yml/badge.svg)](https://github.com/Nyralei/ksniff/actions/workflows/unit-test.yml)
[![lint](https://github.com/Nyralei/ksniff/actions/workflows/lint.yml/badge.svg)](https://github.com/Nyralei/ksniff/actions/workflows/lint.yml)
[![e2e](https://github.com/Nyralei/ksniff/actions/workflows/e2e.yml/badge.svg)](https://github.com/Nyralei/ksniff/actions/workflows/e2e.yml)

A kubectl plugin that uses tcpdump and Wireshark to start a remote packet capture on any pod in your Kubernetes cluster.

### Intro

When working with micro-services, it's often very helpful to capture network traffic between your service and its dependencies. ksniff attaches tcpdump to the target pod and streams the output to your local Wireshark for smooth network debugging.

### Demo
![Demo!](https://i.imgur.com/hWtF9r2.gif)

## Installation

Via [krew](https://krew.sigs.k8s.io/):

    kubectl krew install sniff

Manual installation: download the latest release for your platform from the [releases page](https://github.com/Nyralei/ksniff/releases), extract, and place `kubectl-sniff` on your `$PATH`.

### Wireshark

ksniff requires Wireshark **3.4.0 or newer**. Older versions cannot read the capture format produced by tcpdump. On Ubuntu LTS, use the [Wireshark PPA](https://launchpad.net/~wireshark-dev/+archive/ubuntu/stable) if the stock package is too old.

## Usage

    kubectl sniff <POD_NAME> [-n NAMESPACE] [-c CONTAINER] [-i INTERFACE] [-f FILTER]
                             [-o OUTPUT_FILE] [--mode MODE]

| Flag | Default | Description |
|---|---|---|
| `-n` | current namespace | Namespace of the target pod |
| `-c` | first container | Container to sniff |
| `-i` | `any` | Network interface to capture on |
| `-f` | _(none)_ | tcpdump capture filter |
| `-o` | _(Wireshark)_ | Write capture to file instead of opening Wireshark. Use `-` for stdout |
| `--mode` | `upload` | Sniffing mode: `upload`, `ephemeral`, or `privileged` |
| `-v` | false | Verbose / debug output |

### Sniffing Modes

#### `upload` (default)

Uploads a statically compiled tcpdump binary to the target container and runs it there. Works with any container that has `tar` installed. Requires a local static-tcpdump binary (see [Build](#build)).

    kubectl sniff my-pod -n my-namespace

#### `ephemeral`

Adds a tcpdump [ephemeral container](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/) to the target pod. Does not touch the target container at all.

**Requirements:** Kubernetes 1.25+, `update` permission on `pods/ephemeralcontainers`.

    kubectl sniff my-pod --mode ephemeral

#### `privileged`

Deploys a short-lived privileged pod on the same node as the target pod and uses the container runtime socket to attach to the target container's network namespace. Useful when the target container is scratch or non-privileged and ephemeral containers are not available.

**Supported runtimes:** containerd, docker, cri-o.

Additional flags for privileged mode:

| Flag | Description |
|---|---|
| `--socket` | Container runtime socket path (auto-detected if omitted) |
| `--image` | Privileged helper container image (auto-detected if omitted) |
| `--tcpdump-image` | tcpdump image (auto-detected if omitted) |
| `-s` / `--serviceaccount` | Service account for the privileged pod |
| `--pod-creation-timeout` | How long to wait for the privileged pod to start (default 1m) |

    kubectl sniff my-pod --mode privileged --socket /run/containerd/containerd.sock

### Pipe to stdout

Use `-o -` to pipe raw pcap data to another tool instead of Wireshark:

    kubectl sniff my-pod -f "port 80" -o - | tshark -r -

## Build

Requirements: Go 1.23+

    make linux      # linux/amd64
    make windows
    make darwin

To build a static tcpdump binary (for upload mode):

    make static-tcpdump

To build and push the tcpdump sidecar image:

    make image-push IMAGE_REPO=ghcr.io/youruser/ksniff-tcpdump

## Known Issues

### Wireshark / TShark cannot read pcap

Wireshark may show `UNKNOWN` in the Protocol column, or TShark may report:

```
pcap: network type 276 unknown or unsupported
```

Upgrade Wireshark/TShark to 3.4.0+. On Ubuntu LTS, use the [Wireshark PPA](https://launchpad.net/~wireshark-dev/+archive/ubuntu/stable).

## Contribution

PRs, bug reports, and questions are welcome — open an issue or pull request.
