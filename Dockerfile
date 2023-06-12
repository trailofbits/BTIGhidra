# This Dockerfile sets up an x86_64 build environment for the Binary Type
# Inference Ghidra project. Users should build this Dockerfile and run it while
# mounting a clean BTIGhidra repo:

FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && apt-get upgrade -y && \
    apt-get install -y build-essential curl ca-certificates openjdk-17-jdk unzip

# Switch to non-root user:
RUN useradd --create-home tob
WORKDIR /home/tob
ENV HOME=/home/tob
USER tob
SHELL ["/usr/bin/bash", "-eo", "pipefail", "-c"]

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

ENV PATH="${HOME}/.cargo/bin:${HOME}/.local/bin:${PATH}" \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Rust
RUN rustup install stable

# Just
RUN mkdir -p "${HOME}/.local/bin" && \
    curl -L https://github.com/casey/just/releases/download/1.8.0/just-1.8.0-x86_64-unknown-linux-musl.tar.gz | tar -xz -C "${HOME}/.local/bin"

# Ghidra
RUN curl -L https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3_build/ghidra_10.3_PUBLIC_20230510.zip -o ghidra.zip && \
    unzip ghidra.zip -d "${HOME}/.local/opt" && \
    rm ghidra.zip
ENV GHIDRA_INSTALL_DIR="${HOME}/.local/opt/ghidra_10.3_PUBLIC"
