package binary_type_inference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import generic.jar.ResourceFile;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.GModule;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.util.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import utility.application.ApplicationLayout;

public class GenerateInputsTest extends AbstractGhidraHeadlessIntegrationTest {
  private static TestEnv env;

  private static String pcodeExtractorDir;

  private static Program program;

  @Before
  public void setUp() throws IOException {
    env = new TestEnv(this.getClass().getName());

    pcodeExtractorDir =
        new File(
                System.getProperty("user.dir")
                    + "/../binary_type_inference/cwe_checker/src/ghidra/p_code_extractor")
            .getCanonicalPath();
  }

  @Override
  protected ApplicationLayout createApplicationLayout() throws IOException {
    return new GhidraTestApplicationLayout(new File(getTestDirectoryPath())) {
      @Override
      protected Map<String, GModule> findGhidraModules() throws IOException {
        Map<String, GModule> initModules = new HashMap<>(super.findGhidraModules());

        // Add our current project to the other found Ghidra Modules.
        File ownProjectDir = FileSystems.getDefault().getPath("").toAbsolutePath().toFile();
        String ownModuleName = ownProjectDir.getName();
        GModule ownModule = new GModule(applicationRootDirs, new ResourceFile(ownProjectDir));
        initModules.put(ownModuleName, ownModule);

        return Collections.unmodifiableMap(initModules);
      }
    };
  }

  @After
  public void tearDown() {
    if (program != null) env.release(program);
    program = null;
    env.dispose();
  }

  // Analyze applying types to mooosl and check that the type of the struct is
  // correct at the critical point.

  @Test
  public void testNewMoooslLinkedList() throws Exception {
    // For future reference, to get processor:
    // Processor.findOrPossiblyCreateProcessor("x86")
    LanguageCompilerSpecPair specPair = new LanguageCompilerSpecPair("x86:LE:32:default", "gcc");
    program =
        env.getGhidraProject()
            .importProgram(
                new File(
                    Objects.requireNonNull(
                            GenerateInputsTest.class
                                .getClassLoader()
                                .getResource("binaries/new_moosl_bin"))
                        .getFile()),
                specPair.getLanguage(),
                specPair.getCompilerSpec());
    env.getGhidraProject().analyze(program, false);

    PreservedFunctionList pl = PreservedFunctionList.createFromExternSection(program, true, true);

    var inf = new BinaryTypeInference(program, pl, List.of(pcodeExtractorDir), null, false, false);
    var const_types = inf.produceArtifacts();

    assertTrue("lattice file exists", inf.getLatticeJsonPath().toFile().exists());
    assertTrue(
        "additional constraints file exisits",
        inf.getAdditionalConstraintsPath().toFile().exists());

    inf.getCtypes();

    assertTrue("Ctypes dont exist", inf.getCtypesOutPath().toFile().exists());

    inf.applyCtype(const_types);

    var hopefully_fixed =
        program
            .getFunctionManager()
            .getFunctionAt(program.getAddressFactory().getAddress("0x001014fb"));
    var target_sig = hopefully_fixed.getSignature();

    System.out.println(target_sig);
  }

  @Test
  public void testOldMoooslPropogatePointerTypeFromKeyHash() throws Exception {
    LanguageCompilerSpecPair specPair = new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");
    program =
        env.getGhidraProject()
            .importProgram(
                new File(
                    Objects.requireNonNull(
                            GenerateInputsTest.class
                                .getClassLoader()
                                .getResource("binaries/mooosl"))
                        .getFile()),
                specPair.getLanguage(),
                specPair.getCompilerSpec());

    env.getGhidraProject().getAnalysisOptions(program).setBoolean("Decompiler Parameter ID", true);
    env.getGhidraProject().analyze(program, false);

    AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);

    analysisMgr.waitForAnalysis(null, TaskMonitor.DUMMY);

    System.out.println("Done with analysis");

    // Addr of key hash
    var key_hash_address = program.getAddressFactory().getAddress("0x001013db");

    // Get keyhash function
    var key_hash_func = program.getFunctionManager().getFunctionAt(key_hash_address);

    Objects.requireNonNull(key_hash_func);

    var byte_type = new ByteDataType();
    var byte_ptr = new PointerDataType(byte_type);

    key_hash_func.getParameter(0).setDataType(byte_ptr, SourceType.USER_DEFINED);

    key_hash_func.setSignatureSource(SourceType.USER_DEFINED);

    PreservedFunctionList pl = PreservedFunctionList.createFromExternSection(program, true, true);

    var inf = new BinaryTypeInference(program, pl, List.of(pcodeExtractorDir), null, true, false);
    var const_types = inf.produceArtifacts();

    inf.getCtypes();

    inf.applyCtype(const_types);

    // Addr of lookup
    var lookup_addr = program.getAddressFactory().getAddress("0x001014fb");

    // Lookup func
    var lookup_func = program.getFunctionManager().getFunctionAt(lookup_addr);

    var datatype = lookup_func.getParameter(0).getDataType();

    assertTrue(
        "The in parameter to lookup is directly passed to key hash so the first parameter should learn that it is a pointer",
        datatype instanceof Pointer);
  }

  @Test
  public void testOldMoooslLinkedListGlobalVariable() throws Exception {
    // For future reference, to get processor:
    // Processor.findOrPossiblyCreateProcessor("x86")
    LanguageCompilerSpecPair specPair = new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");
    program =
        env.getGhidraProject()
            .importProgram(
                new File(
                    Objects.requireNonNull(
                            GenerateInputsTest.class
                                .getClassLoader()
                                .getResource("binaries/mooosl"))
                        .getFile()),
                specPair.getLanguage(),
                specPair.getCompilerSpec());

    env.getGhidraProject().getAnalysisOptions(program).setBoolean("Decompiler Parameter ID", true);
    env.getGhidraProject().analyze(program, false);

    AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);

    analysisMgr.waitForAnalysis(null, TaskMonitor.DUMMY);

    System.out.println("Done with analysis");

    PreservedFunctionList pl = PreservedFunctionList.createFromExternSection(program, true, true);

    var inf = new BinaryTypeInference(program, pl, List.of(pcodeExtractorDir), null, true, false);
    var const_types = inf.produceArtifacts();

    assertTrue("lattice file exists", inf.getLatticeJsonPath().toFile().exists());
    assertTrue(
        "additional constraints file exisits",
        inf.getAdditionalConstraintsPath().toFile().exists());

    inf.getCtypes();

    assertTrue("Ctypes dont exist", inf.getCtypesOutPath().toFile().exists());

    inf.applyCtype(const_types);

    var gv_address = program.getAddressFactory().getAddress("0x00104040");
    var hopefully_fixed_data = DataUtilities.getDataAtAddress(program, gv_address);
    var hopefully_fixed_datatype = hopefully_fixed_data.getDataType();

    assertTrue(
        "Global variable for linked list is not a pointer",
        hopefully_fixed_datatype instanceof Pointer);

    var ptr = (Pointer) hopefully_fixed_datatype;
    // Since this is the actual data weve already done one dereference so now we
    // expect to dereference and find the struct itself

    assertTrue("Gv should deref to a struct", ptr.getDataType() instanceof Structure);
  }

  @Test
  public void generateListInputs() throws Exception {
    // For future reference, to get processor:
    // Processor.findOrPossiblyCreateProcessor("x86")
    LanguageCompilerSpecPair specPair = new LanguageCompilerSpecPair("x86:LE:32:default", "gcc");
    program =
        env.getGhidraProject()
            .importProgram(
                new File(
                    Objects.requireNonNull(
                            GenerateInputsTest.class
                                .getClassLoader()
                                .getResource("binaries/list_test.o"))
                        .getFile()),
                specPair.getLanguage(),
                specPair.getCompilerSpec());
    env.getGhidraProject().analyze(program, false);

    Set<Function> pres = new HashSet<>();

    var target_func =
        program
            .getFunctionManager()
            .getFunctionAt(program.getAddressFactory().getAddress("0x1000"));
    pres.add(target_func);

    PreservedFunctionList pl = new PreservedFunctionList(pres);

    var inf = new BinaryTypeInference(program, pl, List.of(pcodeExtractorDir), null, true, false);
    var const_types = inf.produceArtifacts();

    assertTrue("lattice file exists", inf.getLatticeJsonPath().toFile().exists());
    assertTrue(
        "additional constraints file exisits",
        inf.getAdditionalConstraintsPath().toFile().exists());

    inf.getCtypes();

    assertTrue("Ctypes dont exist", inf.getCtypesOutPath().toFile().exists());

    inf.applyCtype(const_types);

    var hopefully_fixed =
        program
            .getFunctionManager()
            .getFunctionAt(program.getAddressFactory().getAddress("0x0000"));
    var target_sig = hopefully_fixed.getSignature();

    System.out.println("zero addr sig: " + target_sig.toString());

    var ptr = target_sig.getArguments()[0];

    assertTrue("Arg to linked list func is not pointer", ptr.getDataType() instanceof Pointer);

    var pointed_to = ((Pointer) ptr.getDataType()).getDataType();

    Objects.requireNonNull(pointed_to);
    System.out.println(pointed_to);

    assertTrue("The pointer does not point to a structure", pointed_to instanceof Structure);

    var struct = (Structure) pointed_to;

    assertEquals(8, struct.getLength());

    assertEquals(2, struct.getNumComponents());

    var should_be_self_pointer = struct.getComponent(0).getDataType();

    assertTrue("First field is not pointer", should_be_self_pointer instanceof Pointer);

    var self_pointer = (Pointer) should_be_self_pointer;
    System.out.println("Later id: " + System.identityHashCode(self_pointer));
    assertEquals(struct, self_pointer.getDataType());

    assertTrue(
        "Second field is not integer",
        struct.getComponent(1).getDataType() instanceof AbstractIntegerDataType);
  }
}
