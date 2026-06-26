package com.xebyte.offline;

import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.headless.HeadlessProgramProvider.ProgramLoadResult;
import junit.framework.TestCase;

/**
 * Offline guard-path coverage for the Ghidra Server open + persist methods
 * added to {@link HeadlessProgramProvider}
 * ({@code openProgramFromServer} / {@code saveAndCheckin} /
 * {@code undoServerCheckout} / {@code addProgramToVersionControl}).
 *
 * <p>The happy paths need a live Ghidra Server with a shared repository and so
 * live in the integration tier. The argument-validation and "program not open"
 * guards, however, are pure logic — they short-circuit before any server or
 * Ghidra Application is touched — and are pinned here so a refactor can't
 * silently turn a clear error into a {@link NullPointerException} or a false
 * success. These were the exact failure modes of the old advisory stubs the
 * new methods replaced.
 */
public class ServerVersionControlTest extends TestCase {

    private HeadlessProgramProvider provider;

    @Override
    protected void setUp() {
        provider = new HeadlessProgramProvider();
    }

    // ------------------------------------------------------------------
    // openProgramFromServer argument validation
    // ------------------------------------------------------------------

    public void testOpenRejectsMissingRepo() {
        ProgramLoadResult r = provider.openProgramFromServer("host", 13100, "", "/Foo.dll", true);
        assertFalse(r.success);
        assertTrue("error mentions repo: " + r.error, r.error.toLowerCase().contains("repo"));
    }

    public void testOpenRejectsNullRepo() {
        ProgramLoadResult r = provider.openProgramFromServer("host", 13100, null, "/Foo.dll", true);
        assertFalse(r.success);
        assertTrue("error mentions repo: " + r.error, r.error.toLowerCase().contains("repo"));
    }

    public void testOpenRejectsMissingPath() {
        ProgramLoadResult r = provider.openProgramFromServer("host", 13100, "agent-shared", "", false);
        assertFalse(r.success);
        assertTrue("error mentions path: " + r.error, r.error.toLowerCase().contains("path"));
    }

    // ------------------------------------------------------------------
    // version-control guards: no such open program
    // ------------------------------------------------------------------

    public void testCheckinUnknownProgramErrorsCleanly() {
        String json = provider.saveAndCheckin("does-not-exist", "msg", false);
        assertTrue("is error json: " + json, json.contains("\"error\""));
        assertTrue("names the program: " + json, json.contains("does-not-exist"));
    }

    public void testUndoCheckoutUnknownProgramErrorsCleanly() {
        String json = provider.undoServerCheckout("does-not-exist", false);
        assertTrue("is error json: " + json, json.contains("\"error\""));
        assertTrue("names the program: " + json, json.contains("does-not-exist"));
    }

    public void testAddToVersionControlUnknownProgramErrorsCleanly() {
        String json = provider.addProgramToVersionControl("does-not-exist", "msg", true);
        assertTrue("is error json: " + json, json.contains("\"error\""));
        assertTrue("names the program: " + json, json.contains("does-not-exist"));
    }
}
