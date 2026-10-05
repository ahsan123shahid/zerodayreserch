import sys
import time
import frida

target = "com.instagram.android"
script_path = sys.argv[1] if len(sys.argv) > 1 else "logs/discover.js"
hold = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

source = open(script_path, encoding="utf-8").read()
device = frida.get_usb_device(timeout=10)
pid = device.spawn([target])
session = device.attach(pid)
device.resume(pid)

script = None
deadline = time.time() + 30
while time.time() < deadline:
    time.sleep(1)
    try:
        script = session.create_script(source)
        script.on("message", lambda message, data: print(message.get("payload", message), flush=True))
        probe = session.create_script("send(typeof Java)")
        got = []
        probe.on("message", lambda m, d: got.append(m.get("payload", m)))
        probe.load()
        if str(got[0]) == "object":
            script.load()
            print("[loaded]", flush=True)
            break
        script = None
        probe.unload()
    except Exception as exc:
        print("[retry]", exc, flush=True)
        script = None

if script is None:
    print("[failed] Java bridge not ready", flush=True)
    sys.exit(1)

time.sleep(hold)
try:
    session.detach()
except Exception:
    pass
print("[detached]", flush=True)
