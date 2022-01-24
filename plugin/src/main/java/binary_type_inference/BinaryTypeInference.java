package binary_type_inference;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Optional;

import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.program.model.listing.Program;
import com.google.common.io.Files;

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

    public BinaryTypeInference(Program prog, PreservedFunctionList preserved) {
        this.prog = prog;
        this.preserved = preserved;
        this.workingDir = Files.createTempDir().toPath();
    }

    private Path getTypeInferenceToolPath() throws OSFileNotFoundException {
        return Path.of(Application.getOSFile(BinaryTypeInferenceRunner.DEFAULT_TOOL_NAME).getAbsolutePath());
    }

    private Path getBinaryPath() {
        return Paths.get(this.prog.getExecutablePath());
    }

    private Path getIROut() {
        return Paths.get(this.workingDir.toString(), "ir.json");
    }

    private FileOutputStream openOutput(Path target) throws FileNotFoundException {
        return new FileOutputStream(target.toFile());
    }

    private Path getAdditionalConstraintsPath() {
        return Paths.get(this.workingDir.toString(), "additional_constraints.pb");
    }

    private Path getInterestingTidsPath() {
        return Paths.get(this.workingDir.toString(), "interesting_tids.pb");
    }

    private Path getLatticeJsonPath() {
        return Paths.get(this.workingDir.toString(), "lattice.json");
    }

    private void produceArtifacts() throws IOException {
        GetBinaryJson ir_generator = new GetBinaryJson(this.prog);
        ir_generator.generateJSONIR(this.getIROut());
        var lattice_gen = new TypeLattice(this.preserved.getTidMap(), new ArrayList<>());
        var output_builder = lattice_gen.getOutputBuilder();
        output_builder.buildAdditionalConstraints(this.openOutput(this.getAdditionalConstraintsPath()));
        output_builder.buildInterestingTids(this.openOutput(this.getInterestingTidsPath()));
        output_builder.buildLattice(this.openOutput(this.getLatticeJsonPath()));
    }

    private Path getCtypesOutPath() {
        return Paths.get(this.workingDir.toString(), "ctypes.pb");
    }

    private void getCtypes() throws IOException {
        var runner = new BinaryTypeInferenceRunner(this.getTypeInferenceToolPath(), this.getBinaryPath(),
                this.getIROut(), this.getLatticeJsonPath(), this.getAdditionalConstraintsPath(),
                this.getInterestingTidsPath(), this.getCtypesOutPath());

        var ty_result = runner.inferTypes();
        if (ty_result.success()) {

        } else {
            // throw exception
        }
    }

    private void applyCtype() {

    }

}
