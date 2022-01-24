package binary_type_inference;

import ctypes.Ctypes.Tid;
import generic.stl.Pair;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

class TypeAnalyzerOptions {
  public Optional<File> preserved_functions_file;

  void setPreservedFunctionsFile(File pth) {
    this.preserved_functions_file = Optional.of(pth);
  }

  void clearPreservedFunctionsFile() {
    this.preserved_functions_file = Optional.empty();
  }
}

class PreservedFunctionList {

  private final Set<Function> preservedFunctions;

  PreservedFunctionList(Set<Function> preservedFunctions) {
    this.preservedFunctions = preservedFunctions;
  }

  private static Optional<Function> parseLineToFunction(Program prog, String line) {
    var addr = prog.getAddressFactory().getAddress(line);
    var func = prog.getFunctionManager().getFunctionAt(addr);
    if (func != null) {
      return Optional.of(func);
    } else {
      return Optional.empty();
    }
  }

  public static Optional<PreservedFunctionList> parseTargetFunctionListFile(
      Program prog, File file_path) {
    try {
      var fl = new FileReader(file_path);
      var lines = new BufferedReader(fl).lines();
      var res =
          Optional.of(
              new PreservedFunctionList(
                  lines
                      .map((String line) -> PreservedFunctionList.parseLineToFunction(prog, line))
                      .filter((var opt) -> opt.isPresent())
                      .map((var opt) -> opt.get())
                      .collect(Collectors.toSet())));
      fl.close();
      return res;
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  public boolean shouldPreserve(Function func) {
    return this.preservedFunctions.contains(func);
  }

  public static Tid functionToTid(Function func) {
    // TODO(ian): This breaks a lot of abstraction layers.
    var addr = func.getEntryPoint().toString();
    var tid_name = String.format("sub_%s", addr);

    return Tid.newBuilder().setAddress(addr).setName(tid_name).build();
  }

  public Map<Tid, FunctionSignature> getTidMap() {
    return this.preservedFunctions.stream()
        .map(
            (Function func) -> {
              var sig = func.getSignature();
              var tid = PreservedFunctionList.functionToTid(func);
              return new Pair<Tid, FunctionSignature>(tid, sig);
            })
        .collect(Collectors.toMap((var pr) -> pr.first, (var pr) -> pr.second));
  }
}

/** Applies inferred types to the program does. */
public class TypeAnalyzer extends AbstractAnalyzer {
  private final TypeAnalyzerOptions opts;

  public TypeAnalyzer() {
    super("Type inference", "Analyzes program for types", AnalyzerType.BYTE_ANALYZER);
    opts = new TypeAnalyzerOptions();
    this.setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean getDefaultEnablement(Program program) {

    return false;
  }

  @Override
  public boolean canAnalyze(Program program) {
    return true;
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    var file = options.getFile("Assume function list", null);

    if (file != null) {
      this.opts.setPreservedFunctionsFile(file);
    } else {
      this.opts.clearPreservedFunctionsFile();
    }
  }

  @Override
  public void registerOptions(Options options, Program program) {

    // TODO: If this analyzer has custom options, register them here

    options.registerOption(
        "Assume function list",
        OptionType.FILE_TYPE,
        null,
        null,
        "the function signatures that are assumed correct");
  }

  @Override
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {

    // TODO: Perform analysis when things get added to the 'program'. Return true if
    // the
    // analysis succeeded.

    if (this.opts.preserved_functions_file.isEmpty()) {
      log.appendException(new RuntimeException("Didnt get preserved functions file"));
      return false;
    }

    var maybe_preserved =
        PreservedFunctionList.parseTargetFunctionListFile(
            program, this.opts.preserved_functions_file.get());

    if (maybe_preserved.isEmpty()) {
      return false;
    }

    var preserved = maybe_preserved.get();

    var bti = new BinaryTypeInference(program, preserved, new ArrayList<>());

    try {
      bti.run();
    } catch (Exception e) {
      log.appendException(e);
      return false;
    }

    return true;
  }
}
