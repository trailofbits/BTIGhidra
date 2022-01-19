package binary_type_inference;

import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class Util {

  public static <T> Stream<T> iteratorToStream(Iterator<T> it) {
    return StreamSupport.stream(
        Spliterators.spliteratorUnknownSize(it, Spliterator.NONNULL), false);
  }
}
