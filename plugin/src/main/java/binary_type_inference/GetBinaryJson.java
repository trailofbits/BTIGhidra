package binary_type_inference;

import java.nio.file.Path;

import org.apache.commons.lang.NotImplementedException;

import ghidra.program.model.listing.Program;

public class GetBinaryJson {

    private final Program prog;

    GetBinaryJson(Program prog) {
        this.prog = prog;
    }

    void generateJSONIR(Path target_out) {
        throw new NotImplementedException();
    }
}
