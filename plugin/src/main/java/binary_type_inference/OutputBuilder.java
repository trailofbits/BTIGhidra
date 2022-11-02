package binary_type_inference;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.protobuf.MessageLite;
import constraints.Constraints.AdditionalConstraint;
import ctypes.Ctypes.Tid;
import generic.stl.Pair;
import ghidra.program.model.data.DataType;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Handles building artifacts required for performing type inference. */
public class OutputBuilder {
  private final List<Pair<String, String>> lattice;
  private final List<AdditionalConstraint> additional_constraints;
  private final List<Tid> interesting_tids;
  private final Map<String, DataType> type_constant_variable_to_datatype;

  public static final String BOTTOM_STRING = "bottom";
  public static final String TOP_STRING = "T";
  // A weak integer is the weakest possible integral type and will construct an
  // integer length depending on the associated size
  public static final String SPECIAL_WEAK_INTEGER = "weak_integer";

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
      List<AdditionalConstraint> additional_constraints,
      List<Tid> interesting_tids,
      Map<String, DataType> type_constant_variable_to_datatype) {
    this.lattice = lattice;
    this.additional_constraints = additional_constraints;
    this.interesting_tids = interesting_tids;
    this.type_constant_variable_to_datatype = type_constant_variable_to_datatype;
  }

  public void addInterestingTids(Collection<Tid> more_tids) {
    this.interesting_tids.addAll(more_tids);
  }

  public Map<String, DataType> getTypeConstantMap() {
    return this.type_constant_variable_to_datatype;
  }

  // TODO(ian): Code gen this with jtd.
  public void buildLattice(File file) throws IOException {
    JsonObject jobj = new JsonObject();

    var bot = new JsonPrimitive(BOTTOM_STRING);
    var top = new JsonPrimitive(TOP_STRING);

    jobj.add("top_handle", top);
    jobj.add("bottom_handle", bot);

    JsonArray arr = new JsonArray();

    for (var lower_handle : this.lattice) {
      var pair = new JsonArray();

      if (lower_handle.first != lower_handle.second) {
        pair.add(lower_handle.first);
        pair.add(lower_handle.second);

        arr.add(pair);
      }
    }

    var all_vars =
        this.lattice.stream()
            .flatMap((Pair<String, String> rel) -> Arrays.asList(rel.first, rel.second).stream())
            .collect(Collectors.toSet());

    for (var v : all_vars) {
      var pair = new JsonArray();

      if (BOTTOM_STRING != v) {
        pair.add(bot);
        pair.add(new JsonPrimitive(v));
        arr.add(pair);
      }
    }

    for (var v : all_vars) {
      if (TOP_STRING != v) {
        var pair = new JsonArray();
        pair.add(new JsonPrimitive(v));
        pair.add(top);
        arr.add(pair);
      }
    }

    jobj.add("less_than_relations_between_handles", arr);

    jobj.add("weakest_integral_type", new JsonPrimitive(OutputBuilder.SPECIAL_WEAK_INTEGER));

    Gson gs = new Gson();
    System.out.println(jobj.toString());
    var wrtr = new FileWriter(file);
    gs.toJson(jobj, wrtr);
    wrtr.close();
  }

  static <T extends MessageLite> void writeLengthDelimitedMessages(
      OutputStream file, Iterable<T> messages) throws IOException {
    byte[] length_buffer = new byte[4];
    ByteBuffer length_buf = ByteBuffer.wrap(length_buffer);
    length_buf.order(ByteOrder.BIG_ENDIAN);
    for (var cons : messages) {
      length_buf.position(0);
      length_buf.putInt(cons.getSerializedSize());
      file.write(length_buf.array());
      cons.writeTo(file);
    }
  }

  public void buildAdditionalConstraints(OutputStream file) throws IOException {
    OutputBuilder.writeLengthDelimitedMessages(file, this.additional_constraints);
    file.close();
  }

  void buildInterestingTids(OutputStream file) throws IOException {
    OutputBuilder.writeLengthDelimitedMessages(file, this.interesting_tids);
    file.close();
  }
}
