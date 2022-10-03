package binary_type_inference;

import ctypes.Ctypes.CTypeMapping;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.apache.commons.vfs2.FileNotFoundException;

public class BinaryTypeInferenceRunner {
  // Executable tool name to search for
  public static final String DEFAULT_TOOL_NAME = "binary_to_types";

  // private final Program program;
  private final Path typeInferenceTool;
  private final Path programLocation;
  private final Path irLocation;
  private final Path typeLatticeLocation;
  private final Path additionalConstraintsLocation;
  private final Path interesting_vars_file;
  private final Path out_protobuf;
  private final Path working_dir;
  private boolean use_aggressive_shared_returns;
  private CTypeMapping ct;

  private Optional<TypeInferenceResult> lastResult = Optional.empty();

  /**
   * Initialize the Binary Type Inference class and use the tool specified.
   *
   * @param typeInferenceToolLocation Path to the type inference tool
   * @param programLocation Path to the file to perform type inference
   * @param irLocation Path to the CWE Checker IR file
   * @param typeLatticeLocation Path to the type lattice file
   * @param additionalConstraintsLocation Path to the file containing additional constraints
   */
  public BinaryTypeInferenceRunner(
      /* Program program, */
      Path typeInferenceToolLocation,
      Path programLocation,
      Path irLocation,
      Path typeLatticeLocation,
      Path additionalConstraintsLocation,
      Path interesting_vars_file,
      Path out_protobuf,
      Path working_dir) {
    // this.program = program;
    this.typeInferenceTool = typeInferenceToolLocation;
    this.programLocation = programLocation;
    this.irLocation = irLocation;
    this.typeLatticeLocation = typeLatticeLocation;
    this.additionalConstraintsLocation = additionalConstraintsLocation;
    this.interesting_vars_file = interesting_vars_file;
    this.out_protobuf = out_protobuf;
    this.working_dir = working_dir;
    this.use_aggressive_shared_returns = false;
  }

  public BinaryTypeInferenceRunner(
      /* Program program, */
      Path typeInferenceToolLocation,
      Path programLocation,
      Path irLocation,
      Path typeLatticeLocation,
      Path additionalConstraintsLocation,
      Path interesting_vars_file,
      Path out_protobuf,
      Path working_dir,
      boolean use_aggressive_shared_returns) {
    // this.program = program;
    this(
        typeInferenceToolLocation,
        programLocation,
        irLocation,
        typeLatticeLocation,
        additionalConstraintsLocation,
        interesting_vars_file,
        out_protobuf,
        working_dir);
    this.use_aggressive_shared_returns = use_aggressive_shared_returns;
  }

  public Optional<TypeInferenceResult> getLastResult() {
    return lastResult;
  }

  public CTypeMapping getCtypeMapping() throws FileNotFoundException, IOException {
    return CTypeMapping.parseFrom(new FileInputStream(this.out_protobuf.toFile()));
  }

  /**
   * Run the type inference tool and collect the results
   *
   * @return The type inference result
   */
  public TypeInferenceResult inferTypes() throws IOException {
    // Call binary type inference tool with arguments
    // Fixes buffering by redirecting output to null

    List<String> init_command =
        Arrays.asList(
            typeInferenceTool.toAbsolutePath().toString(),
            programLocation.toAbsolutePath().toString(),
            irLocation.toAbsolutePath().toString(),
            typeLatticeLocation.toAbsolutePath().toString(),
            additionalConstraintsLocation.toAbsolutePath().toString(),
            this.interesting_vars_file.toAbsolutePath().toString(),
            "--out",
            this.out_protobuf.toString(),
            "--debug_out_dir",
            this.working_dir.toAbsolutePath().toString());

    if (this.use_aggressive_shared_returns) {
      init_command.add("--use_aggressive_shared_returns");
    }

    ProcessBuilder bldr =
        new ProcessBuilder(init_command)
            .redirectOutput(new File("/dev/null"))
            .redirectError(new File("/dev/null"));

    System.out.println(bldr.command());

    var bti = bldr.start();

    var ret = new TypeInferenceResult(bti);
    lastResult = Optional.of(ret);
    return ret;
  }
}
