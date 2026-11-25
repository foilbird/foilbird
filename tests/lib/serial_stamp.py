#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serial console recorder: listen on a unix socket (QEMU connects to it as a client), write every line of the guest's
serial console to a file, each prefixed with the UTC time in milliseconds ("HH:MM:SS.mmm "). Started before QEMU so
that nothing of the early boot is lost; reboots inside the same QEMU process keep the same connection.

    serial_stamp.py <socket> <log>      exits when QEMU closes the connection
"""
import datetime, os, socket, sys

path, log = sys.argv[1], sys.argv[2]
try: os.unlink(path)
except FileNotFoundError: pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path); srv.listen(1)
conn, _ = srv.accept()
buf = b""
with open(log, "ab", buffering=0) as out:
    def emit(line):
        t = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        out.write(t.encode() + b" " + line.rstrip(b"\r") + b"\n")
    while True:
        data = conn.recv(65536)
        if not data:
            break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            emit(line)
    if buf:
        emit(buf)
