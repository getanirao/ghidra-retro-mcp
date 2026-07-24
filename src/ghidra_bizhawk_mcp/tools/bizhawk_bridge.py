import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = int(os.environ.get("BIZHAWK_PORT", "8766"))


class BizhawkBridge:
    """Asyncio TCP server that mediates between MCP tool calls and BizHawk's
    bridge.lua running inside EmuHawk.

    Architecture (inverted transport):
      ghidra-bizhawk-mcp (this server, runs TCP listener)
          ▲
          │  TCP — newline-delimited JSON
          │
      bridge.lua (BizHawk Lua, polls once per frame)

    Wire format:
      Lua → server: "READY\\n" | "RESULT <json>\\n"
      Server → Lua: "NONE\\n" | "<len> <json>\\n"  (length-prefixed INCOMING)
    """

    def __init__(self, host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT):
        self._host = host
        self._port = port
        self._server: asyncio.AbstractServer | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._cmd_id = 0
        self._pending_future: asyncio.Future | None = None
        self._pending_cmd: dict | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    # ── Public API ───────────────────────────────────────────────────────

    async def start(self):
        self._loop = asyncio.get_event_loop()
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
        )
        logger.info("BizHawk bridge listening on %s:%s", self._host, self._port)

    async def stop(self):
        if self._writer:
            self._writer.close()
        if self._server:
            self._server.close()
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def send_command(self, method: str, params: dict | None = None) -> dict:
        """Send a command to BizHawk and wait for the result (≈2 frames ≈33ms).

        Raises RuntimeError if the bridge is not connected or a command is
        already in flight.
        Raises TimeoutError after 10 seconds with no response.
        """
        if not self._connected:
            raise RuntimeError("BizHawk is not connected — launch EmuHawk with --socket_ip=127.0.0.1 --socket_port=8766 --lua=bridge.lua")
        if self._pending_future is not None:
            raise RuntimeError("A command is already in flight")

        self._cmd_id += 1
        cmd = {"id": self._cmd_id, "method": method, "params": params or {}}
        future = self._loop.create_future()

        self._pending_cmd = cmd
        self._pending_future = future

        try:
            return await asyncio.wait_for(future, timeout=10.0)
        except asyncio.TimeoutError:
            self._pending_future = None
            self._pending_cmd = None
            raise TimeoutError("BizHawk did not respond within 10 seconds — is bridge.lua still polling?")

    # ── Internal: TCP handler ────────────────────────────────────────────

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._connected = True
        logger.info("BizHawk client connected")

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                line = line.decode("utf-8", errors="replace").rstrip("\r\n")

                if line == "READY":
                    await self._send_next()

                elif line.startswith("RESULT "):
                    self._handle_result(line[7:])
                    await self._send_next()

        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            self._connected = False
            self._reader = None
            self._writer = None
            logger.info("BizHawk client disconnected")
            if self._pending_future and not self._pending_future.done():
                self._pending_future.set_exception(RuntimeError("BizHawk disconnected"))
                self._pending_future = None
                self._pending_cmd = None

    def _handle_result(self, json_str: str):
        try:
            msg = json.loads(json_str)
        except json.JSONDecodeError:
            return
        if self._pending_future and not self._pending_future.done():
            if "error" in msg:
                err_info = msg["error"]
                self._pending_future.set_exception(
                    RuntimeError(err_info.get("message", str(err_info)))
                )
            else:
                self._pending_future.set_result(msg.get("result"))
            self._pending_future = None

    async def _send_next(self):
        cmd = self._pending_cmd
        if cmd:
            self._pending_cmd = None
            cmd_json = json.dumps(cmd)
            msg = f"{len(cmd_json)} {cmd_json}\n"
            self._writer.write(msg.encode("utf-8"))
            await self._writer.drain()
        else:
            self._writer.write(b"4 NONE\n")
            await self._writer.drain()


# Module-level singleton
_BRIDGE = BizhawkBridge()


def get_bridge() -> BizhawkBridge:
    return _BRIDGE
