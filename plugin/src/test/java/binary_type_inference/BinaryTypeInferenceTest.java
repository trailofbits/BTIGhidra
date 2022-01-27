package binary_type_inference;

import static org.assertj.core.api.Assertions.*;

import com.google.common.io.Files;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.Before;
import org.junit.Test;

public class BinaryTypeInferenceTest {
  private static final Path projectDir = Path.of(System.getProperty("user.dir"));
  private static final Path testDataDir =
      projectDir.getParent().resolve("binary_type_inference").resolve("test_data");

  @Before
  public void setUp() throws IOException {
    // Required for Ghidra search paths to 'os' binary directories
    if (!Application.isInitialized()) {
      Application.initializeApplication(
          new GhidraApplicationLayout(), new ApplicationConfiguration());
    }
  }

  @Test
  public void inferTypes() throws IOException, FileNotFoundException {
    var result_protobuf = Files.createTempDir().toPath();
    var pb_pth = Path.of(result_protobuf.toString(), "ctypes.pb");

    var demo =
        new BinaryTypeInferenceRunner(
            Path.of(
                Application.getOSFile(BinaryTypeInferenceRunner.DEFAULT_TOOL_NAME)
                    .getAbsolutePath()),
            testDataDir.resolve("list_test.o"),
            testDataDir.resolve("list_test.json"),
            testDataDir.resolve("list_lattice.json"),
            testDataDir.resolve("list_additional_constraints.pb"),
            testDataDir.resolve("list_interesting_tids.pb"),
            pb_pth);
    var result = demo.inferTypes();

    assertThat(result.success())
        .overridingErrorMessage(
            new String(result.getStderr().readAllBytes(), StandardCharsets.UTF_8))
        .isTrue();

    var lastResult = demo.getLastResult();
    assertThat(lastResult.orElseThrow()).isSameAs(result);

    demo.getCtypeMapping();
  }
}
