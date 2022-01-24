package binary_type_inference;

import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.TaskMonitor;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang.NotImplementedException;

import aQute.bnd.service.Plugin;

public class GetBinaryJson {

  private final Program prog;
  private final Project project;
  private final ProgramLocation loc;
  private final ProgramSelection sel;
  private final ProgramSelection highlight;
  private final PluginTool tool;
  private final List<String> extra_script_dirs;

  public GetBinaryJson(PluginTool tool, Program prog, Project project, ProgramLocation loc, ProgramSelection sel,
      ProgramSelection highlight, List<String> extra_script_dirs) {
    this.prog = prog;
    this.project = project;
    this.loc = loc;
    this.sel = sel;
    this.highlight = highlight;
    this.tool = tool;
    this.extra_script_dirs = extra_script_dirs;
  }

  void generateJSONIR(Path target_out) throws Exception {
    var st = new GhidraState(tool, project, prog, loc, sel, highlight);

    GhidraScriptUtil.initialize(new BundleHost(), this.extra_script_dirs);
    var scr = GhidraScriptUtil.findScriptByName("PcodeExtractor");
    Objects.requireNonNull(scr);
    var prov = GhidraScriptUtil.getProvider(scr);
    var inst = prov.getScriptInstance(scr, new PrintWriter(System.err));
    String[] args = { target_out.toString() };
    inst.setScriptArgs(args);
    inst.execute(st, TaskMonitor.DUMMY, new PrintWriter(System.err));
  }
}
