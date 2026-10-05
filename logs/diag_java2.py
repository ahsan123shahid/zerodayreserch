import time

import frida

d = frida.get_usb_device(timeout=10)
pid = d.spawn(["com.instagram.android"])
session = d.attach(pid)
d.resume(pid)

samples = []
for i in range(40):
    time.sleep(1)
    try:
        s = session.create_script(
            "send(typeof Java + '|' + (typeof Java !== 'undefined' ? Java.available : 'n/a'))"
        )
        s.on("message", lambda m, _d: samples.append((i, m.get("payload", m))))
        s.load()
        s.unload()
    except Exception as exc:
        samples.append((i, "ERR " + str(exc)))
        break
    if samples and samples[-1][1].startswith("object"):
        break

print(samples, flush=True)
try:
    session.detach()
except Exception:
    pass
