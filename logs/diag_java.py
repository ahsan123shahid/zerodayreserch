import json
import time

import frida

d = frida.get_usb_device(timeout=10)
pid = d.spawn(["com.instagram.android"])
session = d.attach(pid)

out = []


def report(payload):
    out.append(payload)


def make(source):
    script = session.create_script(source)
    script.on("message", lambda m, _d: report(m.get("payload", m)))
    script.load()
    return script


FIRST = "send(JSON.stringify({phase:'spawn', java: typeof Java, arch: Process.arch, id: Process.id}))"
SECOND = "send(JSON.stringify({phase:'resumed', java: typeof Java, avail: (typeof Java !== 'undefined') ? Java.available : null}))"

make(FIRST)
d.resume(pid)
time.sleep(4)
print("spawn:", out, flush=True)

try:
    make(SECOND)
except Exception as exc:
    print("second script error:", exc, flush=True)
time.sleep(2)
print("resumed:", out, flush=True)

try:
    session.detach()
except Exception:
    pass
