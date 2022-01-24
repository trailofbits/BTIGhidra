package binary_type_inference;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.protobuf.MessageLite;
import constraints.Constraints.SubtypingConstraint;
import ctypes.Ctypes.Tid;
import generic.stl.Pair;
import ghidra.program.model.data.DataType;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class OutputBuilder {
  private final List<Pair<String, String>> lattice;
  private final List<SubtypingConstraint> additional_constraints;
  private final List<Tid> interesting_tids;
  private final Map<String, DataType> type_constant_variable_to_datatype;

  public static final String BOTTOM_STRING = "bottom";
  public static final String TOP_STRING = "T";

  /*
   * {
   * "less_than_relations_between_handles": [
   * [
   * "file_descriptor",
   * "int"
   * ],
   * [
   * "int",
   * "T"
   * ],
   * [
   * "bottom",
   * "file_descriptor"
   * ]
   * ],
   * "top_handle": "T",
   * "bottom_handle": "bottom"
   * }
   *
   */

  public OutputBuilder(
      List<Pair<String, String>> lattice,
      List<SubtypingConstraint> additional_constraints,
      List<Tid> interesting_tids,
      Map<String, DataType> type_constant_variable_to_datatype) {
    this.lattice = lattice;
    this.additional_constraints = additional_constraints;
    this.interesting_tids = interesting_tids;
    this.type_constant_variable_to_datatype = type_constant_variable_to_datatype;
  }

  public Map<String, DataType> getTypeConstantMap() {
    return this.type_constant_variable_to_datatype;
  }

  // TODO(ian): Code gen this with jtd.
  void buildLattice(OutputStream file) throws IOException {
    JsonObject jobj = new JsonObject();

    var bot = new JsonPrimitive("bottom");
    var top = new JsonPrimitive("T");

    jobj.add(TOP_STRING, top);
    jobj.add(BOTTOM_STRING, bot);

    JsonArray arr = new JsonArray();

    for (var lower_handle : this.lattice) {
      var pair = new JsonArray();
      pair.add(lower_handle.first);
      pair.add(lower_handle.second);
      arr.add(pair);
    }

    var all_vars =
        this.lattice.stream()
            .flatMap((Pair<String, String> rel) -> Arrays.asList(rel.first, rel.second).stream())
            .collect(Collectors.toSet());

    for (var v : all_vars) {
      var pair = new JsonArray();
      pair.add(bot);
      pair.add(new JsonPrimitive(v));
      arr.add(pair);
    }

    for (var v : all_vars) {
      var pair = new JsonArray();
      pair.add(new JsonPrimitive(v));
      pair.add(top);
      arr.add(pair);
    }

    jobj.add("less_than_relations_between_handles", arr);

    Gson gs = new Gson();
    gs.toJson(jobj, new OutputStreamWriter(file));
  }

  static <T extends MessageLite> void writeLengthDelimitedMessages(
      OutputStream file, Iterable<T> messages) throws IOException {
    byte[] length_buffer = new byte[4];
    ByteBuffer length_buf = ByteBuffer.wrap(length_buffer);
    length_buf.order(ByteOrder.BIG_ENDIAN);
    for (var cons : messages) {
      length_buf.putInt(cons.getSerializedSize());
      cons.writeTo(file);
    }
  }

  void buildAdditionalConstraints(OutputStream file) throws IOException {
    OutputBuilder.writeLengthDelimitedMessages(file, this.additional_constraints);
  }

  void buildInterestingTids(OutputStream file) throws IOException {
    OutputBuilder.writeLengthDelimitedMessages(file, this.interesting_tids);
  }
}
