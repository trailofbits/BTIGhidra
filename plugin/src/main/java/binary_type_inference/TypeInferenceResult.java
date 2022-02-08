package binary_type_inference;

import java.io.InputStream;

/** Class to hold results of the type inference tool. */
public class TypeInferenceResult {

  private final Process typeInference;
  private final InputStream stdout;
  private final InputStream stderr;

  /**
   * Handle the type inference process to generate useful results.
   *
   * @param typeInference the type inference process.
   */
  public TypeInferenceResult(Process typeInference) {
    this.typeInference = typeInference;
    stdout = typeInference.getInputStream();
    stderr = typeInference.getErrorStream();
  }

  public boolean success() {
    try {
      // wait for has a buffer of 32kb which we are blowing away causing permanent
      // hang, do not let block.
      return typeInference.waitFor() == 0;
    } catch (InterruptedException e) {
      return false;
    }
  }

  public InputStream getStdout() {
    return stdout;
  }

  public InputStream getStderr() {
    return stderr;
  }
}
