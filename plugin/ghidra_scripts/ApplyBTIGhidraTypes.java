import binary_type_inference.BinaryTypeInference;
import binary_type_inference.PreservedFunctionList;
import ghidra.app.script.GhidraScript;
import java.nio.file.Path;
import java.util.ArrayList;

public class ApplyBTIGhidraTypes extends GhidraScript {
  @Override
  protected void run() throws Exception {

    var bti = new BinaryTypeInference(
        currentProgram,
        PreservedFunctionList.createFromExternSection(currentProgram, true),
        new ArrayList<>(), null, false, false);

    bti.run();
  }
}
