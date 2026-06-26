package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.headless.GhidraServerManager;
import com.xebyte.headless.HeadlessManagementService;
import com.xebyte.headless.HeadlessProgramProvider;
import junit.framework.TestCase;

/**
 * Offline coverage for the {@code /open_project} param routing added to mount a
 * server-bound (shared) project (bug_featurez_request.md). The endpoint now
 * accepts either {@code path} (local) or {@code repo} (shared, mutually
 * exclusive); the {@code repo} branch auto-connects to the configured server
 * before mounting.
 *
 * <p>These assertions exercise the decision logic that returns before any live
 * Ghidra project is created or any server is reached, so they run offline. The
 * actual server-bound create-or-open is covered by the manual integration
 * checklist (needs a live Ghidra Server + populated repo).
 */
public class OpenProjectSharedMountTest extends TestCase {

    private HeadlessManagementService service() {
        // No GHIDRA_SERVER_* env in the test environment, so the manager has no
        // credentials and connect() fails fast — exactly the offline path we want.
        return new HeadlessManagementService(new HeadlessProgramProvider(), new GhidraServerManager());
    }

    private static String errMessage(Response r) {
        assertTrue("expected Response.Err, got " + r.getClass().getSimpleName(), r instanceof Response.Err);
        return ((Response.Err) r).message();
    }

    /** path and repo are mutually exclusive — passing both is rejected up front. */
    public void testPathAndRepoMutuallyExclusive() {
        Response r = service().openProject("/local.gpr", "agent-shared", "/projects", null);
        assertTrue(errMessage(r).contains("not both"));
    }

    /** Neither path nor repo — the local guard fires and mentions the repo option. */
    public void testNeitherPathNorRepoRejected() {
        Response r = service().openProject(null, null, "/projects", null);
        String msg = errMessage(r);
        assertTrue("names path requirement: " + msg, msg.contains("Project path required"));
        assertTrue("points at repo option: " + msg, msg.contains("repo"));
    }

    /** Blank strings count as absent for both params. */
    public void testBlankParamsRejected() {
        Response r = service().openProject("  ", "  ", "/projects", null);
        // Both treated as absent -> local guard.
        assertTrue(errMessage(r).contains("Project path required"));
    }

    /**
     * repo set but no reachable/credentialed server: the shared branch attempts
     * auto-connect, which fails, and the structured error names the failure.
     */
    public void testSharedMountFailsClosedWhenServerUnavailable() {
        Response r = service().openProject(null, "agent-shared", "/projects", null);
        String msg = errMessage(r);
        assertTrue("reports connect failure: " + msg, msg.contains("Not connected to Ghidra server"));
    }

    /**
     * Local path branch is unchanged: a non-existent project path still returns
     * the "Failed to open project" error (provider returns false offline).
     */
    public void testLocalPathBranchUnchanged() {
        Response r = service().openProject("/no/such/project.gpr", null, "/projects", null);
        assertTrue(errMessage(r).contains("Failed to open project"));
    }
}
