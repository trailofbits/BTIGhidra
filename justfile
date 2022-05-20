format:
  ./plugin/gradlew --project-dir ./plugin spotlessApply

lint:
  ./plugin/gradlew --project-dir ./plugin spotlessCheck

build-native-binary:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain :buildRustBTI

install-native:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain :copyRustBTIDependencies

test:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain --stacktrace -PBTI_AUTO_REMOVE check

install:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain install

reinstall:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain -PBTI_AUTO_REMOVE install

uninstall-bti:
  ./plugin/gradlew --project-dir ./plugin --parallel --console plain -PBTI_AUTO_REMOVE uninstallPreviousBTI

test-native:
  cd ./binary_type_inference && cargo test
