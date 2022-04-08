package binary_type_inference;

import ghidra.program.model.data.DataType;

public interface IUnknownTypeBuilder {
  public DataType getDefaultUnkownType();

  default DataType refineDataTypeWithSize(DataType orig, int new_size) {
    if (this.getDefaultUnkownType().equals(orig)) {
      return this.getUnknownDataTypeWithSize(new_size);
    } else {
      return orig;
    }
  }

  public DataType getUnknownDataTypeWithSize(int new_size);
}
