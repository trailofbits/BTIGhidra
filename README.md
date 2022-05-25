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
# You can run the rest of the commands in the README within the Docker container
$ docker run --rm -t -i -v "$(pwd):/home/tob/workspace" -w /home/tob/workspace bti /bin/bash
```

## Building

Make sure you have an environment variable set to the Ghidra installation directory (this is already set up in the Docker image/container):

```sh
export GHIDRA_INSTALL_DIR=<path_to>/ghidra_10.1.4_PUBLIC
```

Using the [just](https://github.com/casey/just) tool (or view the [`justfile`](./justfile) for common workflow commands):

```sh
just build
```

After building, you can find the zipped plugin in `plugin/dist` directory

## Installing

If you are not using the Docker container, this command will build the zip and install it into the Ghidra directory specified by `GHIDRA_INSTALL_DIR`

```sh
just install
```

If you built using Docker, then you can only use the resulting built plugin on a Linux distribution newer than Ubuntu 20.04.

To install the plugin built by the Docker container, open Ghidra 10.1.4 on your host machine:

1. Navigate and click on `File -> Install Extensions...`
2. Click on the `+` icon in the upper right corner of the window
3. Navigate to the path of this repo under `plugin/dist` and select the latest built `ghidra_10.1.4_PUBLIC_<date>_BTIGhidra.zip` file and hit `OK` to finish the selection
4. Hit `OK` again if you do not see the message to "restart Ghidra"
5. Restart Ghidra

The plugin is now installed!

## Testing

```sh
just test
```

## Usage Notes:

BTIGhidra currently relies on Ghidra's notions of parameters to bind physical locations to function parameters. If the decompiler has function signatures that are correct, you can run the Decompiler Parameter ID analysis to apply the decompile signatures to the ghidra database.
