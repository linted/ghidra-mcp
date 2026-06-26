package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import junit.framework.TestCase;

/**
 * Offline coverage for the headless {@code /list_project_files} fallback
 * (bugreport.md). {@code listProjectFiles} used to hard-fail with "requires
 * GUI mode" under any non-GUI provider; it now first delegates to
 * {@link com.xebyte.core.ProgramProvider#listProjectFiles} so headless
 * providers list the open project's {@code ProjectData} directly.
 *
 * <p>These paths short-circuit before any live Ghidra project is touched, so
 * they run offline.
 */
public class ListProjectFilesHeadlessFallbackTest extends TestCase {

    private ProgramScriptService scriptsWith(com.xebyte.core.ProgramProvider provider) {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        return new ProgramScriptService(provider, ts);
    }

    /** GUI-backed providers inherit the default null: "no headless listing". */
    public void testDefaultProviderHasNoHeadlessListing() {
        assertNull(new StubProgramProvider().listProjectFiles("/"));
    }

    /**
     * When the provider returns a Response, listProjectFiles must return it
     * unchanged — i.e. the headless path is taken before the GUI tool check.
     */
    public void testDelegatesToProviderBeforeGuiCheck() {
        final Response sentinel = Response.ok(java.util.Map.of("project_name", "Headless", "marker", "headless-list"));
        com.xebyte.core.ProgramProvider provider = new StubProgramProvider() {
            @Override
            public Response listProjectFiles(String folderPath) {
                return sentinel;
            }
        };
        Response r = scriptsWith(provider).listProjectFiles(null);
        assertSame(sentinel, r);
        assertTrue(r.toJson().contains("headless-list"));
    }

    /**
     * A provider with no headless listing (returns null) and no PluginTool falls
     * through to the GUI-mode error.
     */
    public void testGuiFallbackMessageIntact() {
        Response r = scriptsWith(new StubProgramProvider()).listProjectFiles("/");
        assertTrue(r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue("mentions GUI mode: " + msg, msg.contains("requires GUI mode")
            || msg.contains("GUI mode"));
    }

    /**
     * Headless provider with no open project returns the structured
     * "No project is currently open" error instead of the GUI-mode error.
     */
    public void testHeadlessListingWithoutProjectIsStructured() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        Response r = provider.listProjectFiles("/");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No project is currently open"));
    }
}
