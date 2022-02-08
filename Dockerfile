# This Dockerfile sets up an x86_64 build environment for the Binary Type
# Inference Ghidra project. Users should build this Dockerfile and run it while
# mounting a clean BTIGhidra repo:
#   docker build -t bti .
#   docker run --rm -t -i -v $(pwd):/home/tob/workspace -w /home/tob/workspace bti /bin/bash
#   $ just install-native
#   $ just install

FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive && \
  apt-get update && apt-get upgrade -y && \
  apt-get install -y build-essential curl ca-certificates openjdk-11-jdk unzip

RUN export DEBIAN_FRONTEND=noninteractive && \
  curl -LO https://github.com/souffle-lang/souffle/releases/download/2.2/x86_64-ubuntu-2004-souffle-2.2-Linux.deb && \
  apt-get install -y ./x86_64-ubuntu-2004-souffle-2.2-Linux.deb && \
  rm x86_64-ubuntu-2004-souffle-2.2-Linux.deb

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
    curl -L https://github.com/casey/just/releases/download/0.10.2/just-0.10.2-x86_64-unknown-linux-musl.tar.gz | tar -xz -C "${HOME}/.local/bin"

# Ghidra
RUN curl -L https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip -o ghidra.zip && \
    unzip ghidra.zip -d "${HOME}/.local/opt" && \
    rm ghidra.zip
ENV GHIDRA_INSTALL_DIR="${HOME}/.local/opt/ghidra_10.1.2_PUBLIC"
