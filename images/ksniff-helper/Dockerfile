FROM alpine:3.23

ARG CRICTL_VERSION=v1.32.0
ARG TARGETARCH

RUN apk add --no-cache jq tcpdump util-linux curl && \
    curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${TARGETARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin/ && \
    apk del curl

CMD ["sh"]