# Only tested on Mac with the following run beforehand:
# brew install filosottile/musl-cross/musl-cross
# rustup target add x86_64-apple-darwin
# rustup target add aarch64-apple-darwin
# rustup target add x86_64-unknown-linux-musl
build-native:
  cd ./binary_type_inference && \
    cargo build --target aarch64-apple-darwin --release && \
    cargo build --target x86_64-apple-darwin --release && \
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc && \
    cargo build --target x86_64-unknown-linux-musl --release

install-native: build-native
  cp -f ./binary_type_inference/target/aarch64-apple-darwin/release/json_to_constraints ./plugin/os/mac_arm_64
  cp -f ./binary_type_inference/target/x86_64-apple-darwin/release/json_to_constraints ./plugin/os/mac_x86_64
  cp -f ./binary_type_inference/target/x86_64-unknown-linux-musl/release/json_to_constraints ./plugin/os/linux_x86_64

format:
  ./plugin/gradlew --project-dir ./plugin spotlessApply

lint:
  ./plugin/gradlew --project-dir ./plugin spotlessCheck

test:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain --stacktrace check

install:
  ./plugin/gradlew --project-dir ./plugin --parallel install

reinstall:
  ./plugin/gradlew --project-dir ./plugin --parallel -PBTI_AUTO_REMOVE install

uninstall-sadie:
  ./plugin/gradlew --project-dir ./plugin --parallel -PBTI_AUTO_REMOVE uninstallPreviousBTI
