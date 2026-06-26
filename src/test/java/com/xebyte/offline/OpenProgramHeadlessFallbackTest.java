package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import junit.framework.TestCase;

/**
 * Offline coverage for the headless {@code /open_program} fallback (bugreport.md
 * Problem 1). {@code openProgramFromProject} used to hard-fail with "requires
 * GUI mode" under any non-GUI provider; it now first delegates to
 * {@link com.xebyte.core.ProgramProvider#openProgramByPath} so headless
 * providers open from the project directly.
 *
 * <p>These paths short-circuit before any live Ghidra program is touched, so
 * they run offline.
 */
public class OpenProgramHeadlessFallbackTest extends TestCase {

    private ProgramScriptService scriptsWith(com.xebyte.core.ProgramProvider provider) {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        return new ProgramScriptService(provider, ts);
    }

    /** GUI-backed providers inherit the default null: "no headless open". */
    public void testDefaultProviderHasNoHeadlessOpen() {
        assertNull(new StubProgramProvider().openProgramByPath("/Foo.dll", false));
    }

    /**
     * When the provider returns a Response, openProgramFromProject must return
     * it unchanged — i.e. the headless path is taken before the GUI tool check.
     */
    public void testDelegatesToProviderBeforeGuiCheck() {
        final Response sentinel = Response.ok(java.util.Map.of("success", true, "marker", "headless-open"));
        com.xebyte.core.ProgramProvider provider = new StubProgramProvider() {
            @Override
            public Response openProgramByPath(String path, boolean autoAnalyze) {
                return sentinel;
            }
        };
        Response r = scriptsWith(provider).openProgramFromProject("/Foo.dll", false);
        assertSame(sentinel, r);
        assertTrue(r.toJson().contains("headless-open"));
    }

    /**
     * A provider with no headless open (returns null) and no PluginTool falls
     * through to the improved GUI error that names the headless routes.
     */
    public void testGuiFallbackMessageNamesHeadlessRoutes() {
        Response r = scriptsWith(new StubProgramProvider()).openProgramFromProject("/Foo.dll", false);
        assertTrue(r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue("mentions GUI mode: " + msg, msg.contains("requires GUI mode")
            || msg.contains("GUI mode"));
        assertTrue("points at server route: " + msg, msg.contains("/open_program_from_server"));
    }

    /** Path guard still fires first, regardless of provider. */
    public void testBlankPathRejected() {
        Response r = scriptsWith(new StubProgramProvider()).openProgramFromProject("  ", false);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program path is required"));
    }

    /**
     * Headless provider with no open project returns the structured
     * load-failure Response (not the GUI error), mirroring
     * /load_program_from_project diagnostics.
     */
    public void testHeadlessOpenWithoutProjectIsStructured() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        Response r = provider.openProgramByPath("/Foo.dll", false);
        assertTrue(r instanceof Response.Ok);
        String json = r.toJson();
        assertTrue("structured failure: " + json, json.contains("\"success\""));
        assertTrue("reports no project: " + json, json.contains("No project open"));
        assertTrue("echoes requested path: " + json, json.contains("/Foo.dll"));
        assertTrue("includes diagnostics: " + json, json.contains("diagnostics"));
    }

    /** Headless provider also enforces the path guard. */
    public void testHeadlessOpenBlankPathRejected() {
        Response r = new HeadlessProgramProvider().openProgramByPath("", false);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program path is required"));
    }
}
