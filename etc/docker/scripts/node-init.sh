#!/bin/bash

cp -rf /var/mizar /home/
mkdir -p /etc/cni/net.d
nsenter -t 1 -m -u -n -i apt-get update -y && nsenter -t 1 -m -u -n -i apt-get install -y \
    sudo \
    rpcbind \
    rsyslog \
    libelf-dev \
    iproute2  \
    net-tools \
    iputils-ping \
    ethtool \
    curl \
    python3 \
    python3-pip && \
nsenter -t 1 -m -u -n -i mkdir -p /opt/cni/bin && \
nsenter -t 1 -m -u -n -i mkdir -p /etc/cni/net.d && \
nsenter -t 1 -m -u -n -i pip3 install /var/mizar/ && \
nsenter -t 1 -m -u -n -i ln -snf /sys/fs/bpf /bpffs && \
nsenter -t 1 -m -u -n -i ln -snf /var/mizar/build/bin /trn_bin && \
nsenter -t 1 -m -u -n -i ln -snf /var/mizar/build/xdp /trn_xdp && \
nsenter -t 1 -m -u -n -i ln -snf /var/mizar/etc/cni/10-mizarcni.conf /etc/cni/net.d/10-mizarcni.conf && \
nsenter -t 1 -m -u -n -i ln -snf /var/mizar/mizar/cni.py /opt/cni/bin/mizarcni && \
nsenter -t 1 -m -u -n -i ln -snf /var/mizar/build/tests/mizarcni.config /etc/mizarcni.config && \
echo "mizar-complete"