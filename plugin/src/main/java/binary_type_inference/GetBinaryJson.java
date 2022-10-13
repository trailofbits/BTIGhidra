package binary_type_inference;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public class GetBinaryJson {

  private final Program prog;
  private final Project project;
  private final ProgramLocation loc;
  private final ProgramSelection sel;
  private final ProgramSelection highlight;
  private final PluginTool tool;
  private final ResourceFile pcodeExtractorScript;
  private Optional<List<Function>> target_functions;

  public GetBinaryJson(PluginTool tool, Program prog, Project project,
                       ProgramLocation loc, ProgramSelection sel,
                       ProgramSelection highlight,
                       List<String> extra_script_dirs,
                       Optional<Set<Function>> target_functions) {
    this.prog = prog;
    this.project = project;
    this.loc = loc;
    this.sel = sel;
    this.highlight = highlight;
    this.tool = tool;
    this.target_functions = target_functions.map((Set<Function> funcs) -> {
      ArrayList<Function> list = new ArrayList<>();
      list.addAll(funcs);
      return list;
    });

    if (GhidraScriptUtil.getBundleHost() == null) {
      GhidraScriptUtil.initialize(new BundleHost(), extra_script_dirs);
    }

    this.pcodeExtractorScript =
        GhidraScriptUtil.findScriptByName("PcodeExtractor");
    Objects.requireNonNull(this.pcodeExtractorScript);
  }

  public GetBinaryJson(PluginTool tool, Program prog, Project project,
                       ProgramLocation loc, ProgramSelection sel,
                       ProgramSelection highlight,
                       List<String> extra_script_dirs) {
    this(tool, prog, project, loc, sel, highlight, extra_script_dirs,
         Optional.empty());
  }

  void generateJSONIR(Path target_out) throws Exception {
    GhidraScriptProvider provider =
        GhidraScriptUtil.getProvider(this.pcodeExtractorScript);
    GhidraScript script = provider.getScriptInstance(
        this.pcodeExtractorScript, new PrintWriter(System.err));
    String[] args = {target_out.toString()};
    script.setScriptArgs(args);

    ResourceFile srcFile = script.getSourceFile();
    String scriptName = srcFile != null
                            ? srcFile.getAbsolutePath()
                            : (script.getClass().getName() + ".class");
    var scriptState = new GhidraState(tool, project, prog, loc, sel, highlight);
    if (this.target_functions.isPresent()) {
      scriptState.addEnvironmentVar("TARGET_FUNCTION_LIST",
                                    this.target_functions.get());
    }
    try {
      script.execute(scriptState, TaskMonitor.DUMMY,
                     new PrintWriter(System.out));
    } catch (Exception exc) {
      String logErrorMsg = "REPORT SCRIPT ERROR: \"" +
                           prog.getExecutablePath() + "\" " + scriptName +
                           " : " + exc.getMessage();
      Msg.error(this, logErrorMsg, exc);
      throw exc;
    }
  }
}
