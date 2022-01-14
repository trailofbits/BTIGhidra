package binary_type_inference;

import ctypes.Ctypes.CTypeMapping;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;
import org.apache.commons.vfs2.FileNotFoundException;

public class BinaryTypeInference {
  // Executable tool name to search for
  public static final String DEFAULT_TOOL_NAME = "json_to_constraints";

  // private final Program program;
  private final Path typeInferenceTool;
  private final Path programLocation;
  private final Path irLocation;
  private final Path typeLatticeLocation;
  private final Path additionalConstraintsLocation;
  private final Path interesting_vars_file;
  private final Path out_protobuf;
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
  public BinaryTypeInference(
      /* Program program, */
      Path typeInferenceToolLocation,
      Path programLocation,
      Path irLocation,
      Path typeLatticeLocation,
      Path additionalConstraintsLocation,
      Path interesting_vars_file,
      Path out_protobuf) {
    // this.program = program;
    this.typeInferenceTool = typeInferenceToolLocation;
    this.programLocation = programLocation;
    this.irLocation = irLocation;
    this.typeLatticeLocation = typeLatticeLocation;
    this.additionalConstraintsLocation = additionalConstraintsLocation;
    this.interesting_vars_file = interesting_vars_file;
    this.out_protobuf = out_protobuf;
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
    ProcessBuilder bldr =
        new ProcessBuilder(
            typeInferenceTool.toAbsolutePath().toString(),
            programLocation.toAbsolutePath().toString(),
            irLocation.toAbsolutePath().toString(),
            typeLatticeLocation.toAbsolutePath().toString(),
            additionalConstraintsLocation.toAbsolutePath().toString(),
            this.interesting_vars_file.toString(),
            "--out",
            this.out_protobuf.toString());

    var bti = bldr.start();

    var ret = new TypeInferenceResult(bti);
    lastResult = Optional.of(ret);
    return ret;
  }

  /**
   * Infer and apply types to the Ghidra program.
   *
   * @return Whether the type inference and application completed successfully.
   */
  public boolean inferAndApplyTypes() throws IOException {
    TypeInferenceResult result = inferTypes();
    if (!result.success()) {
      return false;
    }
    // TODO Do something with output of type inference
    return true;
  }
}
