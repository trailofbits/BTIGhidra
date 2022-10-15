package binary_type_inference;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

class TypeAnalyzerOptions {
  public Optional<File> preserved_functions_file;
  public boolean should_save_output;
  public boolean should_preserve_user_types;
  public boolean use_aggressive_shared_returns;
  public Optional<String> entrypoints;

  public TypeAnalyzerOptions() {
    this.preserved_functions_file = Optional.empty();
    this.should_save_output = false;
    this.should_preserve_user_types = true;
    this.use_aggressive_shared_returns = false;
    this.entrypoints = Optional.empty();
  }

  void setShouldSaveOutput(boolean val) {
    this.should_save_output = val;
  }

  void setPreservedFunctionsFile(File pth) {
    this.preserved_functions_file = Optional.of(pth);
  }

  void clearPreservedFunctionsFile() {
    this.preserved_functions_file = Optional.empty();
  }
}

/** Applies inferred types to the program does. */
public class TypeAnalyzer extends AbstractAnalyzer {
  private final TypeAnalyzerOptions opts;

  private final List<String> extra_script_dir_paths = new ArrayList<>();

  public TypeAnalyzer() {
    super("Type inference", "Analyzes program for types", AnalyzerType.BYTE_ANALYZER);
    opts = new TypeAnalyzerOptions();
    this.setSupportsOneTimeAnalysis();
  }

  public TypeAnalyzer(List<String> extra_script_dir_paths) {
    this();
    this.extra_script_dir_paths.addAll(extra_script_dir_paths);
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
    var new_bool = options.getBoolean("Save to debug directory", this.opts.should_save_output);

    var new_entry_point_list = options.getString("Entry points list", "");
    if (!new_entry_point_list.equals("")) {
      this.opts.entrypoints = Optional.of(new_entry_point_list);
    }

    this.opts.setShouldSaveOutput(new_bool);
    this.opts.should_preserve_user_types =
        options.getBoolean("Preserve user defined types", this.opts.should_preserve_user_types);
    if (file != null) {
      this.opts.setPreservedFunctionsFile(file);
    } else {
      this.opts.clearPreservedFunctionsFile();
    }

    this.opts.use_aggressive_shared_returns =
        options.getBoolean(
            "Use aggressive shared returns (EXPERIMENTAL)",
            this.opts.use_aggressive_shared_returns);
  }

  private static Set<Function> ParseEntryPointList(String list, Program prog) {
    var addrs = list.split(";");
    var res =
        Arrays.stream(addrs)
            .map((String addr) -> prog.getAddressFactory().getAddress(addr))
            .filter(Objects::nonNull)
            .map((Address addr) -> prog.getFunctionManager().getFunctionAt(addr))
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());

    for (var it : res) {
      Msg.debug(TypeAnalyzer.class, it);
    }

    return res;
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

    options.registerOption(
        "Entry points list",
        OptionType.STRING_TYPE,
        "",
        null,
        "List of entry points in the format \"addr;addr\"");

    options.registerOption(
        "Save to debug directory",
        this.opts.should_save_output,
        null,
        "Saves intermediate artifacts instead of removing them after inference.");

    options.registerOption(
        "Preserve user defined types",
        this.opts.should_preserve_user_types,
        null,
        "If true, will add user defined function signatures to the assumed types.");

    options.registerOption(
        "Use aggressive shared returns (EXPERIMENTAL)",
        this.opts.use_aggressive_shared_returns,
        null,
        "Use VSA to try to identify and fixup shared returns... currently high false positive rate");
  }

  @Override
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {

    // TODO: Perform analysis when things get added to the 'program'. Return
    // true if the analysis succeeded.

    Optional<PreservedFunctionList> maybe_preserved = Optional.empty();
    if (this.opts.preserved_functions_file.isPresent()) {
      maybe_preserved =
          PreservedFunctionList.parseTargetFunctionListFile(
              program, this.opts.preserved_functions_file.get());
    }

    if (maybe_preserved.isEmpty()) {
      maybe_preserved =
          Optional.of(
              PreservedFunctionList.createFromExternSection(
                  program, this.opts.should_preserve_user_types));
    }

    var preserved = maybe_preserved.get();

    var bti =
        new BinaryTypeInference(
            program,
            preserved,
            this.extra_script_dir_paths,
            log,
            this.opts.should_save_output,
            this.opts.use_aggressive_shared_returns,
            this.opts.entrypoints.map((String ents) -> ParseEntryPointList(ents, program)));

    try {
      bti.run();
    } catch (Exception e) {
      log.appendException(e);
      return false;
    }

    return true;
  }
}
