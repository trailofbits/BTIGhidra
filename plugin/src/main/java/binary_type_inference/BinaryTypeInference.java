package binary_type_inference;

import com.google.common.io.Files;
import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/*
Path.of(Application.getOSFile(BinaryTypeInferenceRunner.DEFAULT_TOOL_NAME).getAbsolutePath()),
 testDataDir.resolve("list_test.o"),
 testDataDir.resolve("list_test.json"),
 testDataDir.resolve("list_lattice.json"),
 testDataDir.resolve("list_additional_constraints"),
 testDataDir.resolve("list_test_interesting_variables.json"),
 pb_pth*/

public class BinaryTypeInference {
  private final Program prog;
  private final PreservedFunctionList preserved;
  private final Path workingDir;
  private final List<String> extra_script_dirs;

  public BinaryTypeInference(
      Program prog, PreservedFunctionList preserved, List<String> extra_script_dirs) {
    this.prog = prog;
    this.preserved = preserved;
    this.workingDir = Files.createTempDir().toPath();
    // this.workingDir = Paths.get("/tmp");
    this.extra_script_dirs = extra_script_dirs;
  }

  private Path getTypeInferenceToolPath() throws OSFileNotFoundException {
    return Path.of(
        Application.getOSFile(BinaryTypeInferenceRunner.DEFAULT_TOOL_NAME).getAbsolutePath());
  }

  public Path getBinaryPath() {
    return Paths.get(this.prog.getExecutablePath());
  }

  public Path getIROut() {
    return Paths.get(this.workingDir.toString(), "ir.json");
  }

  private FileOutputStream openOutput(Path target) throws FileNotFoundException {
    return new FileOutputStream(target.toFile());
  }

  public Path getAdditionalConstraintsPath() {
    return Paths.get(this.workingDir.toString(), "additional_constraints.pb");
  }

  public Path getInterestingTidsPath() {
    return Paths.get(this.workingDir.toString(), "interesting_tids.pb");
  }

  public Path getLatticeJsonPath() {
    return Paths.get(this.workingDir.toString(), "lattice.json");
  }

  public Map<String, DataType> produceArtifacts() throws Exception {
    GetBinaryJson ir_generator =
        new GetBinaryJson(null, this.prog, null, null, null, null, this.extra_script_dirs);
    ir_generator.generateJSONIR(this.getIROut());

    java.util.function.Function<DataType, Optional<List<String>>> strat =
        (DataType inputtype) -> {
          if (inputtype instanceof AbstractIntegerDataType) {
            return Optional.of(List.of(OutputBuilder.SPECIAL_WEAK_INTEGER));
          } else {
            return Optional.empty();
          }
        };

    // True so that we dont generate type constants for void types.
    var lattice_gen = new TypeLattice(this.preserved.getTidMap(), List.of(strat), true);
    var output_builder = lattice_gen.getOutputBuilder();
    output_builder.buildAdditionalConstraints(this.openOutput(this.getAdditionalConstraintsPath()));
    output_builder.addInterestingTids(
        Util.iteratorToStream(this.prog.getFunctionManager().getFunctions(true))
            .map(PreservedFunctionList::functionToTid)
            .collect(Collectors.toList()));
    output_builder.buildInterestingTids(this.openOutput(this.getInterestingTidsPath()));
    output_builder.buildLattice(this.getLatticeJsonPath().toFile());
    return output_builder.getTypeConstantMap();
  }

  public Path getCtypesOutPath() {
    return Paths.get(this.workingDir.toString(), "ctypes.pb");
  }

  public void getCtypes() throws IOException {
    var runner =
        new BinaryTypeInferenceRunner(
            this.getTypeInferenceToolPath(),
            this.getBinaryPath(),
            this.getIROut(),
            this.getLatticeJsonPath(),
            this.getAdditionalConstraintsPath(),
            this.getInterestingTidsPath(),
            this.getCtypesOutPath(),
            this.workingDir);

    var ty_result = runner.inferTypes();
    if (!ty_result.success()) {
      // throw exception
      throw new RuntimeException(
          "Running type inference failed " + new String(ty_result.getStderr().readAllBytes()));
    }
  }

  public void applyCtype(Map<String, DataType> constants)
      throws IOException, InvalidInputException {
    var ty_lib =
        TypeLibrary.parseFromInputStream(
            new FileInputStream(this.getCtypesOutPath().toFile()),
            constants,
            new IUnknownTypeBuilder() {

              @Override
              public DataType getDefaultUnkownType() {
                // TODO Auto-generated method stub
                return DefaultDataType.dataType;
              }

              @Override
              public DataType getUnknownDataTypeWithSize(int new_size) {
                // TODO Auto-generated method stub
                return Undefined.getUndefinedDataType(new_size);
              }
            },
            this.prog.getDataTypeManager());

    var mapping = ty_lib.buildMapping();

    var func_iter = this.prog.getFunctionManager().getFunctions(true);
    while (func_iter.hasNext()) {
      var func = func_iter.next();
      var tid = PreservedFunctionList.functionToTid(func);
      var new_ty = mapping.getDataTypeForTid(tid);
      if (!this.preserved.shouldPreserve(func) && new_ty.isPresent()) {
        var unwrapped_ty = new_ty.get();
        System.out.println(unwrapped_ty.toString());
        assert (unwrapped_ty instanceof FunctionSignature);
        var sig = (FunctionSignature) unwrapped_ty;
        var args = sig.getArguments();
        func.setReturnType(sig.getReturnType(), SourceType.ANALYSIS);
        var params = func.getParameters();
        var ind = 0;
        for (var par : params) {
          if (ind < args.length) {
            par.setDataType(args[ind].getDataType(), SourceType.ANALYSIS);
          }
          ind++;
        }
      }
    }
  }

  public void run() throws Exception {
    var ty_consts = this.produceArtifacts();
    this.getCtypes();
    this.applyCtype(ty_consts);
  }
}
