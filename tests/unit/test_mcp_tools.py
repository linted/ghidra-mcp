"""
Unit tests for the MCP bridge dynamic tool system.

Tests the thin multiplexer's core functionality: schema parsing, tool
registration, transport mode management, and static tool contracts against the
``ghidra_mcp_bridge`` package.
"""

import asyncio
import inspect
import json
import re
import unittest
from unittest import mock

from ghidra_mcp_bridge import connection, discovery, registry, tools
from ghidra_mcp_bridge.config import ENDPOINT_TIMEOUTS, STATIC_TOOL_NAMES
from ghidra_mcp_bridge.schema import build_tool_function, parse_schema


class TestTransportModes(unittest.TestCase):
    """Test transport mode state management."""

    def test_initial_state(self):
        """Transport mode is always one of the three known values."""
        self.assertIn(connection.transport_mode(), ("none", "uds", "tcp"))

    def test_do_request_raises_when_disconnected(self):
        """do_request should raise ConnectionError when no transport active."""
        connection.reset()
        with self.assertRaises(ConnectionError):
            connection.do_request("GET", "/test")


class TestStaticTools(unittest.TestCase):
    """Test that static MCP tools are always available."""

    def test_list_instances_is_static(self):
        self.assertIn("list_instances", STATIC_TOOL_NAMES)

    def test_connect_instance_is_static(self):
        self.assertIn("connect_instance", STATIC_TOOL_NAMES)

    def test_list_instances_returns_json(self):
        """list_instances should return valid JSON with an instances list."""
        result = tools.list_instances()
        data = json.loads(result)
        self.assertIn("instances", data)
        self.assertIsInstance(data["instances"], list)


class TestConnectInstanceRollback(unittest.TestCase):
    """A failed connect must not leave a mismatched transport/tool state.

    On schema-fetch failure the bridge drops the just-activated transport and
    tears down stale dynamic tools, so nothing dispatches against the new
    (broken) instance. reset() preserves _connected_project (now the just-tried
    project) so lazy reconnect targets the right instance.
    """

    def setUp(self):
        # Fully snapshot/restore connection globals -- reset() deliberately
        # preserves _connected_project, which would otherwise leak into other
        # tests (see TestConnectInstanceTcpProject).
        saved = (
            connection._active_socket,
            connection._active_tcp,
            connection._transport_mode,
            connection._connected_project,
        )

        def _restore_conn():
            (
                connection._active_socket,
                connection._active_tcp,
                connection._transport_mode,
                connection._connected_project,
            ) = saved

        self.addCleanup(_restore_conn)
        self.addCleanup(registry.register_tools_from_schema, [])

        # Register a dynamic tool to stand in for a prior session's schema, so
        # we can assert it's cleared on rollback.
        registry.register_tools_from_schema(
            [
                {
                    "name": "stale_probe_tool",
                    "endpoint": "/stale_probe",
                    "http_method": "GET",
                    "input_schema": {"type": "object", "properties": {}},
                }
            ]
        )

    def test_uds_schema_failure_resets_and_clears_tools(self):
        connection.activate_uds("/tmp/sock-old", "OldProject")
        self.assertTrue(registry.dynamic_tool_names())  # precondition

        instances = [{"project": "NewProject", "socket": "/tmp/sock-new", "pid": 42}]
        with mock.patch.object(discovery, "discover_instances", return_value=instances), \
             mock.patch.object(
                 registry,
                 "fetch_and_register_schema",
                 side_effect=RuntimeError("Failed to fetch schema: HTTP 500"),
             ):
            result = json.loads(asyncio.run(tools.connect_instance("NewProject")))

        self.assertIn("error", result)
        # Transport dropped — not stranded half-connected on the new socket.
        self.assertEqual(connection.transport_mode(), "none")
        self.assertIsNone(connection.active_socket())
        # Reconnect targets the project we just tried, not the stale one.
        self.assertEqual(connection.connected_project(), "NewProject")
        # Stale dynamic tools are gone.
        self.assertEqual(registry.dynamic_tool_names(), [])

    def test_tcp_schema_failure_resets_and_clears_tools(self):
        connection.activate_uds("/tmp/sock-old", "OldProject")
        self.assertTrue(registry.dynamic_tool_names())  # precondition

        # No UDS instances -> TCP fallback path; force the env override so we
        # take the deterministic tcp_url branch.
        with mock.patch.object(discovery, "discover_instances", return_value=[]), \
             mock.patch.dict("os.environ", {"GHIDRA_MCP_URL": "http://127.0.0.1:8089"}), \
             mock.patch.object(
                 discovery, "_resolve_tcp_project", return_value="NewProject"
             ), \
             mock.patch.object(
                 registry,
                 "fetch_and_register_schema",
                 side_effect=RuntimeError("boom"),
             ):
            result = json.loads(asyncio.run(tools.connect_instance("NewProject")))

        self.assertIn("error", result)
        self.assertEqual(connection.transport_mode(), "none")
        self.assertIsNone(connection.active_tcp())
        self.assertEqual(connection.connected_project(), "NewProject")
        self.assertEqual(registry.dynamic_tool_names(), [])


class TestRegisterToolsTransactional(unittest.TestCase):
    """register_tools_from_schema must not tear down old tools if it fails early."""

    def tearDown(self):
        registry.register_tools_from_schema([])

    def test_normalize_failure_preserves_existing_tools(self):
        schema = [
            {
                "name": "rollback_probe_tool",
                "endpoint": "/rollback_probe",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        count = registry.register_tools_from_schema(schema)
        self.assertEqual(count, 1)
        before = list(registry.dynamic_tool_names())
        self.assertIn("rollback_probe_tool", before)

        # A normalization failure happens before any teardown, so the previously
        # registered tools must still be live afterward.
        with mock.patch.object(
            registry,
            "_normalize_tool_def_names",
            side_effect=RuntimeError("bad schema"),
        ):
            with self.assertRaises(RuntimeError):
                registry.register_tools_from_schema([{"endpoint": "/whatever"}])

        self.assertEqual(registry.dynamic_tool_names(), before)


class TestRegisterToolCategoryCoercion(unittest.TestCase):
    """A null/non-string upstream category must not break tag construction.

    fastmcp validates that every tag is a string; a None or non-str category
    raises pydantic ValidationError. The registry coerces such values to the
    sentinel "unknown" so the tool still registers.
    """

    def tearDown(self):
        registry.register_tools_from_schema([])

    def _tags_for(self, name):
        tool = asyncio.run(registry.mcp.local_provider.get_tool(name))
        return tool.tags

    def test_none_category_coerced_to_unknown(self):
        count = registry.register_tools_from_schema(
            [
                {
                    "name": "none_category_tool",
                    "endpoint": "/none_category",
                    "http_method": "GET",
                    "input_schema": {"type": "object", "properties": {}},
                    "category": None,
                }
            ]
        )
        self.assertEqual(count, 1)
        self.assertEqual(self._tags_for("none_category_tool"), {"unknown"})

    def test_non_string_category_coerced_to_unknown(self):
        count = registry.register_tools_from_schema(
            [
                {
                    "name": "int_category_tool",
                    "endpoint": "/int_category",
                    "http_method": "GET",
                    "input_schema": {"type": "object", "properties": {}},
                    "category": 123,
                }
            ]
        )
        self.assertEqual(count, 1)
        self.assertEqual(self._tags_for("int_category_tool"), {"unknown"})

    def test_empty_string_category_coerced_to_unknown(self):
        count = registry.register_tools_from_schema(
            [
                {
                    "name": "empty_category_tool",
                    "endpoint": "/empty_category",
                    "http_method": "GET",
                    "input_schema": {"type": "object", "properties": {}},
                    "category": "",
                }
            ]
        )
        self.assertEqual(count, 1)
        self.assertEqual(self._tags_for("empty_category_tool"), {"unknown"})

    def test_valid_category_preserved(self):
        count = registry.register_tools_from_schema(
            [
                {
                    "name": "valid_category_tool",
                    "endpoint": "/valid_category",
                    "http_method": "GET",
                    "input_schema": {"type": "object", "properties": {}},
                    "category": "analysis",
                }
            ]
        )
        self.assertEqual(count, 1)
        self.assertEqual(self._tags_for("valid_category_tool"), {"analysis"})


class TestTcpReconnect(unittest.TestCase):
    """A dropped/reset TCP session must auto-reconnect over TCP.

    Before the fix, _try_reconnect() only scanned for UDS sockets, so a TCP-only
    setup (no AF_UNIX, or GHIDRA_MCP_URL override) could never recover and was
    told to "open the project" in a UI it may not be driving.
    """

    def setUp(self):
        saved = (
            connection._active_socket,
            connection._active_tcp,
            connection._transport_mode,
            connection._connected_project,
            connection._last_tcp_url,
            connection._last_transport,
        )

        def _restore():
            (
                connection._active_socket,
                connection._active_tcp,
                connection._transport_mode,
                connection._connected_project,
                connection._last_tcp_url,
                connection._last_transport,
            ) = saved

        self.addCleanup(_restore)

    def test_reset_tcp_session_reconnects_over_tcp(self):
        connection.activate_tcp("http://127.0.0.1:8089", project="Proj")
        connection.reset()  # simulate a dropped session
        self.assertEqual(connection.transport_mode(), "none")
        # Reconnect hints survive reset().
        self.assertEqual(connection.last_tcp_url(), "http://127.0.0.1:8089")
        self.assertEqual(connection.last_transport(), "tcp")

        with mock.patch.object(
            registry, "fetch_and_register_schema", return_value=5
        ) as fetch, mock.patch(
            "ghidra_mcp_bridge.discovery.discover_instances"
        ) as discover:
            self.assertTrue(connection._try_reconnect())

        fetch.assert_called_once()
        discover.assert_not_called()  # TCP path must not need UDS discovery
        self.assertEqual(connection.transport_mode(), "tcp")
        self.assertEqual(connection.active_tcp(), "http://127.0.0.1:8089")

    def test_tcp_reconnect_failure_resets_transport(self):
        connection.activate_tcp("http://127.0.0.1:8089", project="Proj")
        connection.reset()

        with mock.patch.object(
            registry,
            "fetch_and_register_schema",
            side_effect=ConnectionError("refused"),
        ), mock.patch(
            "ghidra_mcp_bridge.discovery.discover_instances", return_value=[]
        ):
            self.assertFalse(connection._try_reconnect())

        # A failed reconnect must not strand a broken active transport.
        self.assertEqual(connection.transport_mode(), "none")
        # Hints remain so a later call can retry.
        self.assertEqual(connection.last_tcp_url(), "http://127.0.0.1:8089")

    def test_ensure_connected_message_is_tcp_oriented(self):
        connection.activate_tcp("http://127.0.0.1:8089", project="Proj")
        connection.reset()

        with mock.patch.object(
            registry,
            "fetch_and_register_schema",
            side_effect=ConnectionError("refused"),
        ), mock.patch(
            "ghidra_mcp_bridge.discovery.discover_instances", return_value=[]
        ):
            msg = connection._ensure_connected()

        self.assertIsNotNone(msg)
        self.assertIn("http://127.0.0.1:8089", msg)
        self.assertIn("not reachable", msg)

    def test_tcp_preferred_then_uds_fallback(self):
        """A TCP-last session that can't reach TCP falls back to UDS scan."""
        connection.activate_tcp("http://127.0.0.1:8089", project="Proj")
        connection.reset()

        call_order = []

        def _fetch():
            # Fail the first (TCP) attempt, succeed on the UDS attempt.
            call_order.append(connection.transport_mode())
            if connection.transport_mode() == "tcp":
                raise ConnectionError("tcp down")
            return 3

        with mock.patch.object(
            registry, "fetch_and_register_schema", side_effect=_fetch
        ), mock.patch(
            "ghidra_mcp_bridge.discovery.discover_instances",
            return_value=[{"project": "Proj", "socket": "/tmp/sock"}],
        ):
            self.assertTrue(connection._try_reconnect())

        self.assertEqual(call_order, ["tcp", "uds"])
        self.assertEqual(connection.transport_mode(), "uds")

    def test_uds_session_still_reconnects_over_uds(self):
        """Regression: the UDS-first path is unchanged for UDS sessions."""
        connection.activate_uds("/tmp/old-sock", "Proj")
        connection.reset()
        self.assertEqual(connection.last_transport(), "uds")

        with mock.patch.object(
            registry, "fetch_and_register_schema", return_value=1
        ), mock.patch(
            "ghidra_mcp_bridge.discovery.discover_instances",
            return_value=[{"project": "Proj", "socket": "/tmp/new-sock"}],
        ):
            self.assertTrue(connection._try_reconnect())

        self.assertEqual(connection.transport_mode(), "uds")
        self.assertEqual(connection.active_socket(), "/tmp/new-sock")


class TestEndpointTimeouts(unittest.TestCase):
    """Test endpoint timeout configuration."""

    def test_all_timeouts_positive(self):
        for name, timeout in ENDPOINT_TIMEOUTS.items():
            self.assertGreater(timeout, 0, f"Timeout for {name} should be positive")

    def test_script_timeouts_high(self):
        self.assertGreaterEqual(ENDPOINT_TIMEOUTS.get("run_ghidra_script", 0), 600)
        self.assertGreaterEqual(ENDPOINT_TIMEOUTS.get("run_script_inline", 0), 600)

    def test_default_exists(self):
        self.assertIn("default", ENDPOINT_TIMEOUTS)


class TestSchemaFormat(unittest.TestCase):
    """Test that tool schema format matches expectations."""

    def test_register_with_all_json_types(self):
        """Schema with all JSON types should produce correct Python signatures."""
        schema = {
            "properties": {
                "str_param": {"type": "string"},
                "int_param": {"type": "integer"},
                "bool_param": {"type": "boolean"},
                "num_param": {"type": "number"},
            },
            "required": ["str_param"],
        }
        fn = build_tool_function("/test", "POST", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 5)
        self.assertIn("dry_run", sig.parameters)

    def test_schema_with_descriptions(self):
        """Schema properties with descriptions should not affect function building."""
        schema = {
            "properties": {
                "address": {
                    "type": "string",
                    "description": "The function address or name",
                },
            },
            "required": ["address"],
        }
        fn = build_tool_function("/decompile_function", "GET", schema)
        self.assertTrue(callable(fn))

    def test_parsed_schema_tool_names_match_capi_regex(self):
        """Every parsed MCP-visible tool name should be safe for Copilot/CAPI."""
        raw = {
            "tools": [
                {"path": "/regular_tool", "method": "GET", "params": []},
                {"path": "/debugger/status", "method": "GET", "params": []},
                {"path": "/server/status", "method": "GET", "params": []},
            ]
        }
        pattern = re.compile(r"^[a-zA-Z0-9_-]+$")
        for tool in parse_schema(raw):
            self.assertRegex(tool["name"], pattern)


if __name__ == "__main__":
    unittest.main()
