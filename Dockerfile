# This Dockerfile sets up an x86_64 build environment for the Binary Type
# Inference Ghidra project. Users should build this Dockerfile and run it while
# mounting a clean BTIGhidra repo:

FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && apt-get upgrade -y && \
    apt-get install -y build-essential curl ca-certificates openjdk-11-jdk unzip

# Switch to non-root user:
RUN useradd --create-home tob
WORKDIR /home/tob
ENV HOME=/home/tob
USER tob
SHELL ["/usr/bin/bash", "-eo", "pipefail", "-c"]

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

ENV PATH="${HOME}/.cargo/bin:${HOME}/.local/bin:${PATH}" \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64

# Rust
RUN rustup install stable

# Just
RUN mkdir -p "${HOME}/.local/bin" && \
    curl -L https://github.com/casey/just/releases/download/1.1.3/just-1.1.3-x86_64-unknown-linux-musl.tar.gz | tar -xz -C "${HOME}/.local/bin"

# Ghidra
RUN curl -L https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.5_build/ghidra_10.1.5_PUBLIC_20220726.zip -o ghidra.zip && \
    unzip ghidra.zip -d "${HOME}/.local/opt" && \
    rm ghidra.zip
ENV GHIDRA_INSTALL_DIR="${HOME}/.local/opt/ghidra_10.1.5_PUBLIC"
