package binary_type_inference;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;

public interface IUnknownTypeBuilder {
  public DataType getDefaultUnkownType();

  default DataType refineDataTypeWithSize(DataType orig, int new_size) {
    if (this.getDefaultUnkownType().equals(orig)) {
      return this.getUnknownDataTypeWithSize(new_size);
    } else if (IntegerDataType.dataType.equals(orig)) {
      return this.getWeakestIntegerTypeWithSize(new_size);
    } else {

      return orig;
    }
  }

  public DataType getWeakestIntegerTypeWithSize(int new_size);

  public DataType getUnknownDataTypeWithSize(int new_size);
}
