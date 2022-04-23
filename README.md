# Binary Type Inference Ghidra Plugin

Please be sure to grab the submodules:

```sh
git submodule update --init --recursive
```

# Installing

Make sure you have an environment variable set to the Ghidra installation directory:

```sh
export GHIDRA_INSTALL_DIR=<path_to>/ghidra_10.1.1_PUBLIC
```

Using the [just](https://github.com/casey/just) tool (or view the [`justfile`](./justfile) for common workflow commands):

```sh
just install
```

# Testing

```sh
just test
```

# Usage Notes:

BTIGhidra currently relies on Ghidra's notions of parameters to bind physical locations to function parameters. If the decompiler has function signatures that are correct, you can run the Decompiler Parameter ID analysis to apply the decompile signatures to the ghidra database.
