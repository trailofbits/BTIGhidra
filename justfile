# Only tested on Mac with the following run beforehand:
# brew install filosottile/musl-cross/musl-cross
# rustup target add x86_64-apple-darwin
# rustup target add aarch64-apple-darwin
# rustup target add x86_64-unknown-linux-musl

platform := replace(os(),"macos","mac") + "_" + replace(arch(), "aarch64","arm_64")

build-native-binary: 
  cd ./binary_type_inference && cargo build --release

install-native: build-native-binary
  rm -f ./plugin/os/{{platform}}/json_to_constraints
  cp ./binary_type_inference/target/release/json_to_constraints ./plugin/os/{{platform}}/

format:
  ./plugin/gradlew --project-dir ./plugin spotlessApply

lint:
  ./plugin/gradlew --project-dir ./plugin spotlessCheck

test:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain --stacktrace check

# This is a hack to handle upstream issues, the ghidra script provider will crash if this isnt handled
patch-ghidra:
  rm -f $GHIDRA_INSTALL_DIR/Ghidra/Features/GhidraServer/data/yajsw-beta-13.01/lib/extended/vfs-webdav/slf4j-jdk14-1.5.0.jar

install: patch-ghidra
  ./plugin/gradlew --project-dir ./plugin --parallel install
  mkdir -p $GHIDRA_INSTALL_DIR/Ghidra/Extensions/BTIGhidra/ghidra_scripts/
  cp -r binary_type_inference/cwe_checker/src/ghidra/p_code_extractor/* $GHIDRA_INSTALL_DIR/Ghidra/Extensions/BTIGhidra/ghidra_scripts/

reinstall:
  ./plugin/gradlew --project-dir ./plugin --parallel -PBTI_AUTO_REMOVE install

uninstall-bti:
  ./plugin/gradlew --project-dir ./plugin --parallel -PBTI_AUTO_REMOVE uninstallPreviousBTI

test-native:
  cd ./binary_type_inference && cargo test