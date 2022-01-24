package binary_type_inference;

import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import java.io.File;
import java.io.IOException;
import java.util.Objects;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class GenerateInputsTest extends AbstractGhidraHeadlessIntegrationTest {
  private static TestEnv env;

  private static Program program;

  private final ClassLoader classLoader = getClass().getClassLoader();

  @Before
  public void setUp() throws IOException {
    env = new TestEnv(this.getClass().getName());
  }

  @After
  public void tearDown() {
    if (program != null) env.release(program);
    program = null;
    env.dispose();
  }

  @Test
  public void generateListInputs()
      throws IOException, InvalidNameException, DuplicateNameException, CancelledException,
          VersionException, MemoryAccessException {
    // For future reference, to get processor:
    // Processor.findOrPossiblyCreateProcessor("x86")
    LanguageCompilerSpecPair specPair = new LanguageCompilerSpecPair("x86:LE:32:default", "gcc");
    program =
        env.getGhidraProject()
            .importProgram(
                new File(
                    Objects.requireNonNull(
                            GenerateInputsTest.class
                                .getClassLoader()
                                .getResource("binaries/list_test.o"))
                        .getFile()),
                specPair.getLanguage(),
                specPair.getCompilerSpec());
    env.getGhidraProject().analyze(program, false);
  }
}
