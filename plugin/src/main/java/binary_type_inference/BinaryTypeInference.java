package binary_type_inference;

import binary_type_inference.TypeLibrary.Types;
import com.google.common.io.Files;
import ctypes.Ctypes.Tid;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
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
  private final MessageLog log;

  public BinaryTypeInference(
      Program prog,
      PreservedFunctionList preserved,
      List<String> extra_script_dirs,
      MessageLog log,
      boolean should_save_output) {
    this.log = log;
    this.prog = prog;
    this.preserved = preserved;

    if (should_save_output) {
      // TODO(Ian): wish we could use java.io.tmpdir here to be cross platform
      // but seems like ghidra sets this to a different tmp dir that is deleted.
      this.workingDir = Paths.get("/tmp");
    } else {
      this.workingDir = Files.createTempDir().toPath();
    }

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

  public Path getWorkingDir() {
    return this.workingDir;
  }

  private static java.util.function.Function<DataType, Optional<List<String>>> strat =
      (DataType inputtype) -> {
        if (inputtype instanceof AbstractIntegerDataType) {
          return Optional.of(List.of(OutputBuilder.SPECIAL_WEAK_INTEGER));
        } else {
          return Optional.empty();
        }
      };

  public static TypeLattice createTypeLattice(PreservedFunctionList preserved) {
    return new TypeLattice(preserved.getTidMap(), List.of(strat), true);
  }

  public Map<String, DataType> produceArtifacts() throws Exception {
    GetBinaryJson ir_generator =
        new GetBinaryJson(null, this.prog, null, null, null, null, this.extra_script_dirs);
    ir_generator.generateJSONIR(this.getIROut());

    // True so that we dont generate type constants for void types.
    var lattice_gen = createTypeLattice(this.preserved);
    var output_builder = lattice_gen.getOutputBuilder();
    output_builder.buildAdditionalConstraints(this.openOutput(this.getAdditionalConstraintsPath()));
    output_builder.addInterestingTids(
        Util.iteratorToStream(this.prog.getFunctionManager().getFunctions(true))
            .map(PreservedFunctionList::functionToTid)
            .collect(Collectors.toList()));

    // Make global variables interesting
    output_builder.addInterestingTids(
        this.getGlobalSymbols().stream()
            .map(BinaryTypeInference::globalSymbolToTid)
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

  // Currently, we only guess types for globals in the symb tab that are dynamic
  private List<Symbol> getGlobalSymbols() {
    var ref_man = this.prog.getReferenceManager();
    var symb_tab = this.prog.getSymbolTable();
    ArrayList<Symbol> tot_vars = new ArrayList<>();
    for (var blk : this.prog.getMemory().getBlocks()) {
      if (blk.isExecute()) {
        var addrs = new AddressSet(blk.getStart(), blk.getEnd());
        var ref_source_iter = ref_man.getReferenceSourceIterator(addrs, true);
        while (ref_source_iter.hasNext()) {
          var curr_src_addr = ref_source_iter.next();
          for (var ref : ref_man.getReferencesFrom(curr_src_addr)) {
            if (ref.isMemoryReference() && ref.getReferenceType().isData()) {
              var symb = symb_tab.getPrimarySymbol(ref.getToAddress());
              if (symb != null) {
                tot_vars.add(symb);
              }
            }
          }
        }
      }
    }
    return tot_vars;
  }

  private static Tid globalSymbolToTid(Symbol symb) {
    // TODO(ian): This breaks a lot of abstraction layers.
    var tid_name = String.format("glb_%s_%s", symb.getAddress().toString(), symb.getName());
    return Tid.newBuilder().setAddress(symb.getAddress().toString()).setName(tid_name).build();
  }

  private void applyCtypesToGlobals(Types mapping) throws CodeUnitInsertionException {
    for (var symb : this.getGlobalSymbols()) {
      if (SymbolUtilities.isDynamicSymbolPattern(symb.getName(), false)) {
        var symb_tid = BinaryTypeInference.globalSymbolToTid(symb);
        var maybe_data = mapping.getDataTypeForTid(symb_tid);
        if (maybe_data.isPresent()) {
          // Since we are setting the type of the data itself we have already
          // done one deref so we need to deref this datatype when we apply it
          // to the address
          if (maybe_data.get() instanceof Pointer) {
            var ptr = (Pointer) maybe_data.get();
            DataUtilities.createData(
                this.prog,
                symb.getAddress(),
                ptr.getDataType(),
                ptr.getDataType().getLength(),
                false,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
          }
        }
      }
    }
  }

  public void applyCtype(Map<String, DataType> constants)
      throws IOException, InvalidInputException, CodeUnitInsertionException {
    var dtm = this.prog.getDataTypeManager();
    var unknown_ty_builder =
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

          @Override
          public DataType getWeakestIntegerTypeWithSize(int new_size) {
            // TODO Auto-generated method stub
            return IntegerDataType.getUnsignedDataType(new_size, dtm);
          }
        };
    var ty_lib =
        TypeLibrary.parseFromInputStream(
            new FileInputStream(this.getCtypesOutPath().toFile()),
            constants,
            unknown_ty_builder,
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
        func.setReturnType(
            unknown_ty_builder.refineDataTypeWithSize(
                sig.getReturnType(), func.getReturn().getLength()),
            SourceType.ANALYSIS);
        var params = func.getParameters();
        var ind = 0;
        for (var par : params) {
          if (ind < args.length) {
            par.setDataType(
                unknown_ty_builder.refineDataTypeWithSize(args[ind].getDataType(), par.getLength()),
                SourceType.ANALYSIS);
          }
          ind++;
        }
      }
    }

    this.applyCtypesToGlobals(mapping);
  }

  public void run() throws Exception {
    var ty_consts = this.produceArtifacts();
    this.getCtypes();
    this.applyCtype(ty_consts);
  }
}
