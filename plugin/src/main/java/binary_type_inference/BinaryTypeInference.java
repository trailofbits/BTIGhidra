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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.Stack;
import java.util.stream.Collectors;

/**
 * A utility class that runs type inference on a target program, then applies the inferred types to
 * the ghidra database.
 */
public class BinaryTypeInference {
  private final Program prog;
  private final PreservedFunctionList preserved;
  private final Path workingDir;
  private final List<String> extra_script_dirs;
  private final MessageLog log;
  private final boolean use_aggressive_shared_returns;
  private Optional<Set<Function>> entry_point_functions;

  /**
   * @param prog the target program to perform type inference on
   * @param preserved a set of functions where the types of those functions are taken as given and
   *     will not be changed by type inference
   * @param extra_script_dirs extra script dirs to search for the json export script
   * @param log where to log messages to
   * @param should_save_output wether to save the generated artifacts and debug info for this type
   *     inference run
   * @param use_aggressive_shared_returns wether to use reaching definitions to try to identify
   *     shared returns in tail call situations (volatile currently)
   */
  public BinaryTypeInference(
      Program prog,
      PreservedFunctionList preserved,
      List<String> extra_script_dirs,
      MessageLog log,
      boolean should_save_output,
      boolean use_aggressive_shared_returns) {
    this(
        prog,
        preserved,
        extra_script_dirs,
        log,
        should_save_output,
        use_aggressive_shared_returns,
        Optional.empty());
  }

  /**
   * @param prog the target program to perform type inference on
   * @param preserved a set of functions where the types of those functions are taken as given and
   *     will not be changed by type inference
   * @param extra_script_dirs extra script dirs to search for the json export script
   * @param log where to log messages to
   * @param should_save_output wether to save the generated artifacts and debug info for this type
   *     inference run
   * @param use_aggressive_shared_returns wether to use reaching definitions to try to identify
   *     shared returns in tail call situations (volatile currently)
   * @param entry_point_functions a set of entrypoints to limit analysis to, type inference will
   *     only consider and affect the entrypoint functions and any functions transitively called
   *     from the entry points
   */
  public BinaryTypeInference(
      Program prog,
      PreservedFunctionList preserved,
      List<String> extra_script_dirs,
      MessageLog log,
      boolean should_save_output,
      boolean use_aggressive_shared_returns,
      Optional<Set<Function>> entry_point_functions) {
    this.entry_point_functions = entry_point_functions;
    this.log = log;
    this.prog = prog;
    this.preserved = preserved;
    this.use_aggressive_shared_returns = use_aggressive_shared_returns;

    if (should_save_output) {
      // TODO(Ian): wish we could use java.io.tmpdir here to be cross platform
      // but seems like ghidra sets this to a different tmp dir that is deleted.
      this.workingDir = Paths.get("/tmp");
    } else {
      this.workingDir = Files.createTempDir().toPath();
    }

    this.extra_script_dirs = extra_script_dirs;
  }

  /**
   * Collects the set of functions transitively called by the entry points of this type inference
   * run
   *
   * @return the set of reached functions from the entry points
   */
  private Optional<Set<Function>> getTransitiveClosureOfEntryPoints() {
    if (this.entry_point_functions.isEmpty()) {
      return Optional.empty();
    }

    Set<Function> res = new HashSet<>();

    Stack<Function> wlist = new Stack<>();

    for (var ent : this.entry_point_functions.get()) {
      wlist.add(ent);
    }

    while (!wlist.isEmpty()) {
      var curr = wlist.pop();

      if (!res.contains(curr)) {
        res.add(curr);
        for (var f : this.entry_point_functions.get()) {
          for (var insn : this.prog.getListing().getInstructions(f.getBody(), true)) {
            for (var ref : insn.getReferencesFrom()) {
              if (ref.getReferenceType().isCall()) {
                var canidate_func =
                    this.prog.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (Objects.nonNull(canidate_func)) {
                  wlist.add(canidate_func);
                }
              }
            }
          }
        }
      }
    }

    return Optional.of(res);
  }

  /**
   * The path to the underyling binary that takes exported IR jsons and produces type information
   *
   * @return the path to the type inference binary
   * @throws OSFileNotFoundException if the binary is not available to Ghidra in the correct OS
   *     directory
   */
  private Path getTypeInferenceToolPath() throws OSFileNotFoundException {
    return Path.of(
        Application.getOSFile(BinaryTypeInferenceRunner.DEFAULT_TOOL_NAME).getAbsolutePath());
  }

  /**
   * Gets the path to the target binary
   *
   * @return finds the target binary that was imported into Ghidra, this won't work if the binary
   *     has been moved since importing
   */
  public Path getBinaryPath() {
    return Paths.get(this.prog.getExecutablePath());
  }

  /**
   * Gets the binary ir.json after artifacts have been exported
   *
   * @return the path to the generated ir.json
   */
  public Path getIROut() {
    return Paths.get(this.workingDir.toString(), "ir.json");
  }

  /**
   * Utility method for opening files for writing
   *
   * @param target the path to write to
   * @return an output stream to write to
   * @throws FileNotFoundException the path to the file does not exist
   */
  private FileOutputStream openOutput(Path target) throws FileNotFoundException {
    return new FileOutputStream(target.toFile());
  }

  /**
   * Where additional constraints (ie. known function signatures) will be generated
   *
   * @return the path to the additional constraints file
   */
  public Path getAdditionalConstraintsPath() {
    return Paths.get(this.workingDir.toString(), "additional_constraints.pb");
  }

  /**
   * Gets the path to interesting tids (type variables to solve for)
   *
   * @return the path to the interesting tids file
   */
  public Path getInterestingTidsPath() {
    return Paths.get(this.workingDir.toString(), "interesting_tids.pb");
  }

  /**
   * Path to the type lattice describing subtyping relationships on primitive types
   *
   * @return the path to the type lattice json
   */
  public Path getLatticeJsonPath() {
    return Paths.get(this.workingDir.toString(), "lattice.json");
  }

  /**
   * The working directory where type inference artifacts will be stored
   *
   * @return the path to the working directory
   */
  public Path getWorkingDir() {
    return this.workingDir;
  }

  /**
   * The strategy for generating less than relations, currently the lattice is quite course, the
   * only relation we hold onto is that all integer datatypes are a subtype of the weakest integer
   * type.
   */
  private static java.util.function.Function<DataType, Optional<List<String>>> strat =
      (DataType inputtype) -> {
        if (inputtype instanceof AbstractIntegerDataType) {
          return Optional.of(List.of(OutputBuilder.SPECIAL_WEAK_INTEGER));
        } else {
          return Optional.empty();
        }
      };

  /**
   * Generate the primitive type lattice from a preserved function list which defines the required
   * constants to express those signatures
   *
   * @param preserved the signatures to generate constants from
   * @return the lattice of primitive types
   */
  public static TypeLattice createTypeLattice(PreservedFunctionList preserved) {
    return new TypeLattice(preserved.getTidMap(), List.of(strat), true);
  }

  /**
   * Produces the inputs to type inference including the json IR, type lattice, interesting TID
   * file, and additional constraints file.
   *
   * @return a map from type variable name to datatype for converting inferred types back to ghidra
   *     datatypes
   * @throws Exception if an exception is thrown by the IR exporter script while running.
   */
  public Map<String, DataType> produceArtifacts() throws Exception {
    GetBinaryJson ir_generator =
        new GetBinaryJson(
            null,
            this.prog,
            null,
            null,
            null,
            null,
            this.extra_script_dirs,
            this.getTransitiveClosureOfEntryPoints());
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

  /**
   * Get the ctypes output path
   *
   * @return the path to the inferred ctypes file
   */
  public Path getCtypesOutPath() {
    return Paths.get(this.workingDir.toString(), "ctypes.pb");
  }

  /**
   * Runs the type inference binary to generate the inferred ctypes file
   *
   * @throws IOException if there is an IO error starting the type inference process
   */
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
            this.workingDir,
            this.use_aggressive_shared_returns);

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

  /**
   * Applies a generated ctype file to the target program
   *
   * @param constants a mapping between type identifiers and constant ghidra datatypes
   * @throws IOException on a failure to open the inferred c type file
   * @throws InvalidInputException if the return type is invalid for the target function (not a
   *     fixed length)
   * @throws CodeUnitInsertionException failure to insert data types into the data section to
   *     represent globals
   */
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

  /**
   * Runs a type inference on a target binary: generates the required artifacts, infers the ctypes,
   * then applies those ctypes to the ghidra DB.
   *
   * @throws Exception an error occurs during inference or application.
   */
  public void run() throws Exception {
    var ty_consts = this.produceArtifacts();
    this.getCtypes();
    this.applyCtype(ty_consts);
  }
}
