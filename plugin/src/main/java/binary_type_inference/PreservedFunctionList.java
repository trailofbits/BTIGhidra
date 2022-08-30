package binary_type_inference;

import ctypes.Ctypes.Tid;
import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class PreservedFunctionList {

  private final Set<Function> preservedFunctions;

  public static PreservedFunctionList createFromExternSection(
      Program prog, boolean keepAllUserDefinedTypes) {
    var pres = new HashSet<Function>();

    for (var func : prog.getFunctionManager().getExternalFunctions()) {
      if (func.getSignatureSource() != SourceType.USER_DEFINED) {
        Arrays.stream(func.getFunctionThunkAddresses())
            .map((Address addr) -> prog.getFunctionManager().getFunctionAt(addr))
            .filter(Objects::nonNull)
            .forEach((Function thunk) -> pres.add(thunk));
        pres.add(func);
      }
    }

    if (keepAllUserDefinedTypes) {
      for (var func : prog.getFunctionManager().getFunctions(true)) {
        if (func.getSignatureSource() == SourceType.USER_DEFINED) {
          pres.add(func);
        }
      }
    }

    return new PreservedFunctionList(pres);
  }

  public PreservedFunctionList(Set<Function> preservedFunctions) {
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
