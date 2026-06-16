"""Unit-test fixtures for the ghidra_mcp_bridge package.

The bridge keeps its live-connection state in module-level globals
(``connection._active_socket`` / ``_active_tcp`` / ``_transport_mode``). Salvaged
unit tests mutate that state via ``connection.activate_*``; reset it around every
test so the suite stays order-independent.
"""

import pytest

from ghidra_mcp_bridge import connection


def _clear_connection_state():
    # reset() deliberately preserves the reconnect hints; for test isolation we
    # drop them too so a transport activated in one test can't bleed into the
    # next via the persisted _last_* / _connected_project globals.
    connection.reset()
    connection._connected_project = None
    connection._last_tcp_url = None
    connection._last_transport = "none"


@pytest.fixture(autouse=True)
def _reset_connection_state():
    _clear_connection_state()
    yield
    _clear_connection_state()
