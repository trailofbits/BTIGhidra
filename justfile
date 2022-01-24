# Only tested on Mac with the following run beforehand:
# brew install filosottile/musl-cross/musl-cross
# rustup target add x86_64-apple-darwin
# rustup target add aarch64-apple-darwin
# rustup target add x86_64-unknown-linux-musl

platform := replace(os(),"macos","mac") + "_" + replace(arch(), "aarch64","arm_64")

build-native-binary: 
  cd ./binary_type_inference && cargo build --release

build-native-datalog: build-native-binary
  cd ./binary_type_inference && souffle -o ./target/release/lowertypes ./lowering/type_inference.dl


install-native: build-native-datalog build-native-binary
  rm ./plugin/os/{{platform}}/json_to_constraints
  rm ./plugin/os/{{platform}}/lowertypes
  cp ./binary_type_inference/target/release/json_to_constraints ./plugin/os/{{platform}}/
  cp ./binary_type_inference/target/release/lowertypes ./plugin/os/{{platform}}/

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
