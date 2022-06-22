package binary_type_inference;

import constraints.Constraints.AdditionalConstraint;
import constraints.Constraints.DerivedTypeVariable;
import constraints.Constraints.Field;
import constraints.Constraints.FieldLabel;
import constraints.Constraints.SubtypingConstraint;
import ctypes.Ctypes.Tid;
import generic.stl.Pair;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.FunctionSignature;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class Retval {
  private final Set<DataType> type_constants;
  private final List<AdditionalConstraint> constraints;

  public Set<DataType> getType_constants() {
    return type_constants;
  }

  public List<AdditionalConstraint> getConstraints() {
    return constraints;
  }

  public Retval() {
    this.type_constants = new HashSet<>();
    this.constraints = new ArrayList<>();
  }

  public Retval(Retval other) {
    this.type_constants = new HashSet<DataType>(other.type_constants);
    this.constraints = new ArrayList<>(other.constraints);
  }

  public Retval merge(Retval other) {
    var newVal = new Retval(this);
    newVal.constraints.addAll(other.constraints);
    newVal.type_constants.addAll(other.type_constants);
    return newVal;
  }

  public void addSubtyCons(AdditionalConstraint sty) {
    this.constraints.add(sty);
  }

  public void addTypeConstant(DataType constant) {
    this.type_constants.add(constant);
  }
}

// A TypeLatice is generated from a set of fixed signatures.
// Each fixed signature attempts to generate constraints for injecting
// uninterpreted type constants.
// Also supports overriding relations to avoid a flat lattice. These are
// functions that compute the less than operations.

// Signatures are collected into constraints. When we no longer can emit a
// constraint, we get a type constant for that data type.
public class TypeLattice {
  private final boolean shouldIgnoreVoidPointers;

  private final Map<Tid, FunctionSignature> fixed_signatures;

  private final List<Function<DataType, Optional<List<String>>>> less_than_relation_strategy;

  private final Map<DataType, DerivedTypeVariable> memoized_types;

  public TypeLattice(
      Map<Tid, FunctionSignature> fixed_signatures,
      List<Function<DataType, Optional<List<String>>>> less_than_relation_strategy,
      boolean shouldIgnoreVoidPointers) {
    this.fixed_signatures = fixed_signatures;
    this.less_than_relation_strategy = less_than_relation_strategy;
    this.shouldIgnoreVoidPointers = shouldIgnoreVoidPointers;
    this.memoized_types = new HashMap<>();
  }

  private Optional<Retval> constraintsForReturn(Tid tid, DataType ty) {
    if (this.shouldIgnoreVoidPointers && TypeLattice.isVoidPointer(ty)) {
      return Optional.empty();
    }

    var func_tvar = TypeLattice.tid_to_tvar(tid);

    var dtv =
        DerivedTypeVariable.newBuilder()
            .setBaseVar(func_tvar)
            .addFieldLabels(FieldLabel.newBuilder().setOutParam(0))
            .build();

    var repr_for_ty = this.representation_for_datatype(ty, tid);

    var subty = SubtypingConstraint.newBuilder().setLhs(dtv).setRhs(repr_for_ty.first).build();
    var add_cons = AdditionalConstraint.newBuilder().setSubTy(subty).setTargetVariable(tid);

    repr_for_ty.second.addSubtyCons(add_cons.build());

    return Optional.of(repr_for_ty.second);
  }

  private static boolean isVoidPointer(DataType ty) {
    return (ty instanceof Pointer) && (((Pointer) ty).getDataType() instanceof VoidDataType);
  }

  private Optional<Retval> constraintsForParam(int idx, Tid tid, DataType ty) {
    if (this.shouldIgnoreVoidPointers && TypeLattice.isVoidPointer(ty)) {
      return Optional.empty();
    }

    var repr = representation_for_datatype(ty, tid);

    var new_cons =
        SubtypingConstraint.newBuilder()
            .setLhs(repr.first)
            .setRhs(dtv_for_param_of_tid(idx, tid))
            .build();

    var add_cons = AdditionalConstraint.newBuilder().setSubTy(new_cons).setTargetVariable(tid);

    repr.second.addSubtyCons(add_cons.build());

    return Optional.of(repr.second);
  }

  private static String tid_to_tvar(Tid tid) {
    return tid.getName();
  }

  private static DerivedTypeVariable dtv_for_param_of_tid(int idx, Tid tid) {
    return DerivedTypeVariable.newBuilder()
        .setBaseVar(tid_to_tvar(tid))
        .addFieldLabels(FieldLabel.newBuilder().setInParam(idx))
        .build();
  }

  private static String data_type_to_type_variable(DataType dt) {
    if (dt.getUniversalID() != null) {
      return "data_type_with_id_" + dt.getUniversalID().toString();
    } else {
      return "data_type_with_display_name"
          + dt.getPathName().toString().replaceAll("/", "")
          + "_"
          + dt.getDisplayName();
    }
  }

  private static DerivedTypeVariable.Builder data_type_to_derived_variable(DataType dt) {
    return DerivedTypeVariable.newBuilder().setBaseVar(TypeLattice.data_type_to_type_variable(dt));
  }

  private static Optional<Field> FieldMember(int offset, DataType dt) {
    var sz = dt.getLength();
    if (sz > 0) {
      return Optional.of(Field.newBuilder().setByteOffset(sz).setBitSize(sz * 8).build());
    } else {
      return Optional.empty();
    }
  }

  private static DerivedTypeVariable.Builder get_ptr_dtv_for_type(
      Pointer pty, constraints.Constraints.Pointer load_or_store) {
    var repr = data_type_to_derived_variable(pty);
    var maybe_field_mem = FieldMember(0, pty.getDataType());

    repr.addFieldLabels(FieldLabel.newBuilder().setPtr(load_or_store));

    if (maybe_field_mem.isPresent()) {
      repr.addFieldLabels(FieldLabel.newBuilder().setField(maybe_field_mem.get()));
    }

    return repr;
  }

  private Pair<DerivedTypeVariable, Retval> representation_for_pointer(
      Pointer ptr, Tid affecting_tid) {
    var load_repr =
        TypeLattice.get_ptr_dtv_for_type(
            ptr, constraints.Constraints.Pointer.POINTER_LOAD_UNSPECIFIED);
    var store_repr =
        TypeLattice.get_ptr_dtv_for_type(ptr, constraints.Constraints.Pointer.POINTER_STORE);

    var pointedToRes = this.representation_for_datatype(ptr.getDataType(), affecting_tid);

    var load_cons =
        SubtypingConstraint.newBuilder().setLhs(pointedToRes.first).setRhs(load_repr).build();
    var store_cons =
        SubtypingConstraint.newBuilder().setLhs(store_repr).setRhs(pointedToRes.first).build();

    var retval = pointedToRes.second;

    var add_cons_load =
        AdditionalConstraint.newBuilder()
            .setSubTy(load_cons)
            .setTargetVariable(affecting_tid)
            .build();
    var add_store_cons =
        AdditionalConstraint.newBuilder()
            .setSubTy(store_cons)
            .setTargetVariable(affecting_tid)
            .build();

    retval.addSubtyCons(add_cons_load);
    retval.addSubtyCons(add_store_cons);

    return new Pair<DerivedTypeVariable, Retval>(
        data_type_to_derived_variable(ptr).build(), retval);
  }

  private Pair<DerivedTypeVariable, Retval> representation_for_structure(
      Structure struct, Tid affecting_tid) {
    var tot = new Retval();
    var struct_base_dtv = TypeLattice.data_type_to_derived_variable(struct).build();
    for (var comp : struct.getComponents()) {
      var repr_of_field =
          this.representation_for_datatype_recursive(
              comp.getDataType(), affecting_tid, struct, struct_base_dtv);
      var struct_var = TypeLattice.data_type_to_derived_variable(struct);
      tot.merge(repr_of_field.second);
      var field_access =
          struct_var
              .addFieldLabels(
                  FieldLabel.newBuilder()
                      .setField(
                          Field.newBuilder()
                              .setBitSize(comp.getLength() * 8)
                              .setByteOffset(comp.getOffset())))
              .build();

      var field_access_cons =
          AdditionalConstraint.newBuilder()
              .setSubTy(
                  SubtypingConstraint.newBuilder()
                      .setLhs(repr_of_field.first)
                      .setRhs(field_access)
                      .build())
              .setTargetVariable(affecting_tid)
              .build();
      tot.addSubtyCons(field_access_cons);
    }

    return new Pair<DerivedTypeVariable, Retval>(
        TypeLattice.data_type_to_derived_variable(struct).build(), tot);
  }

  private Pair<DerivedTypeVariable, Retval> representation_for_datatype_no_memo(
      DataType dt, Tid affecting_tid) {
    if (dt instanceof Pointer) {
      return representation_for_pointer((Pointer) dt, affecting_tid);
      // TODO(ian): maybe expand to unions.
    } else if (dt instanceof Structure) {
      return representation_for_structure((Structure) dt, affecting_tid);
    } else {
      // generate fall through constant
      var type_const = TypeLattice.data_type_to_derived_variable(dt).build();
      var context = new Retval();

      context.addTypeConstant(dt);

      return new Pair<DerivedTypeVariable, Retval>(type_const, context);
    }
  }

  private Pair<DerivedTypeVariable, Retval> representation_for_datatype(
      DataType dt, Tid affecting_tid) {

    if (this.memoized_types.containsKey(dt)) {
      return new Pair<DerivedTypeVariable, Retval>(this.memoized_types.get(dt), new Retval());
    } else {
      var res = this.representation_for_datatype_no_memo(dt, affecting_tid);
      this.memoized_types.put(dt, res.first);
      return res;
    }
  }

  private Pair<DerivedTypeVariable, Retval> representation_for_datatype_recursive(
      DataType dt,
      Tid affecting_tid,
      DataType representing_insert,
      DerivedTypeVariable to_insert_var) {
    this.memoized_types.put(representing_insert, to_insert_var);
    return this.representation_for_datatype(dt, affecting_tid);
  }

  private Retval constraintsForSignature(Tid tid, FunctionSignature sig) {
    System.out.println("Working on signature for: " + sig.getPrototypeString());
    Retval total = new Retval();
    int idx = 0;
    for (var arg : sig.getArguments()) {
      var maybe_val = this.constraintsForParam(idx, tid, arg.getDataType());
      if (maybe_val.isPresent()) {
        total = total.merge(maybe_val.get());
      }

      idx++;
    }

    var maybe_ret_cons = this.constraintsForReturn(tid, sig.getReturnType());
    if (maybe_ret_cons.isPresent()) {
      total = total.merge(maybe_ret_cons.get());
    }

    return total;
  }

  private Retval collectSignatureConstraints() {
    return this.fixed_signatures.entrySet().stream()
        .map((var sig) -> this.constraintsForSignature(sig.getKey(), sig.getValue()))
        .reduce(new Retval(), (Retval x, Retval y) -> x.merge(y));
  }

  private Stream<Pair<String, String>> applyLessThanStrategies(DataType type_const) {
    var const_str = TypeLattice.data_type_to_type_variable(type_const);
    for (var strat : this.less_than_relation_strategy) {
      var maybe_res = strat.apply(type_const);
      if (maybe_res.isPresent()) {
        var dts = maybe_res.get();
        return dts.stream()
            .map((String things_greater) -> new Pair<String, String>(const_str, things_greater));
      }
    }

    return Stream.empty();
  }

  private Stream<Pair<String, String>> constantsToLattice(Set<DataType> constants) {
    var bottom_cons =
        Stream.concat(
            constants.stream()
                .map(
                    (DataType target_constant) -> {
                      return new Pair<String, String>(
                          OutputBuilder.BOTTOM_STRING,
                          TypeLattice.data_type_to_type_variable(target_constant));
                    }),
            Stream.of(
                new Pair<String, String>(
                    OutputBuilder.BOTTOM_STRING, OutputBuilder.SPECIAL_WEAK_INTEGER)));

    var top_cons =
        Stream.concat(
            constants.stream()
                .map(
                    (DataType target_constant) -> {
                      return new Pair<String, String>(
                          TypeLattice.data_type_to_type_variable(target_constant),
                          OutputBuilder.TOP_STRING);
                    }),
            Stream.of(
                new Pair<String, String>(
                    OutputBuilder.SPECIAL_WEAK_INTEGER, OutputBuilder.TOP_STRING)));

    var generated_cons =
        constants.stream()
            .flatMap(
                (DataType target_constant) -> {
                  return this.applyLessThanStrategies(target_constant);
                });

    return Stream.concat(Stream.concat(bottom_cons, top_cons), generated_cons);
  }

  public OutputBuilder getOutputBuilder() {
    var collected_res = this.collectSignatureConstraints();

    var constraints = collected_res.getConstraints();
    var lattice =
        this.constantsToLattice(collected_res.getType_constants()).collect(Collectors.toList());
    var interesting_tids = this.fixed_signatures.keySet().stream().collect(Collectors.toList());

    var const_map =
        collected_res.getType_constants().stream()
            .collect(
                Collectors.toMap(
                    (DataType ty_const) -> TypeLattice.data_type_to_type_variable(ty_const),
                    (DataType ty_const) -> ty_const));

    return new OutputBuilder(lattice, constraints, interesting_tids, const_map);
  }
}
