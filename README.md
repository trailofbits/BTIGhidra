# Binary Type Inference Ghidra Plugin

Please be sure to grab the submodules:

```sh
git submodule update --init --recursive
```

## Build Requirements

The following must be installed:

* Java 11+
* gradle 7+
* Rust toolchain with Cargo build system

There is a [Dockerfile](./Dockerfile) that provides an environment that is able to build and run the tests. Run the following from the root directory of this repo

```sh
$ docker build -t bti .
# Drop into the built container with this repo mapped in
# You can run the rest of the commands within the Docker container
$ docker run --rm -t -i -v "$(pwd):/home/tob/workspace" -w /home/tob/workspace bti /bin/bash
```

## Building

Make sure you have an environment variable set to the Ghidra installation directory:

```sh
export GHIDRA_INSTALL_DIR=<path_to>/ghidra_10.1.4_PUBLIC
```

Using the [just](https://github.com/casey/just) tool (or view the [`justfile`](./justfile) for common workflow commands):

```sh
just build
```

After building, you can find the zipped extension in `plugin/dist` directory

## Installing

This command will build the zip and install it into the Ghidra directory specified by `GHIDRA_INSTALL_DIR`

```sh
just install
```

## Testing

```sh
just test
```

## Usage Notes:

BTIGhidra currently relies on Ghidra's notions of parameters to bind physical locations to function parameters. If the decompiler has function signatures that are correct, you can run the Decompiler Parameter ID analysis to apply the decompile signatures to the ghidra database.
