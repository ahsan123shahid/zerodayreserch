import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] JS Broadcast: {message['payload']}")
    else:
        print(f"[-] Target Interface Exception: {message}")

try:
    # 1. Connected Android Device context capture karna
    device = frida.get_usb_device()
    print("[+] Framework bound to USB/Emulator Target.")

    # 2. Instagram process launch karna
    pid = device.spawn(["com.instagram.android"])
    session = device.attach(pid)
    print(f"[+] Instagram App process spawned successfully. PID: {pid}")

    # 3. Custom Javascript payload inject karna
    with open("bypass_pinning.js", "r", encoding="utf-8") as f:
        js_code = f.read()

    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()
    print("[+] JavaScript configuration arrays injected into active memory.")

    # Resume the application process stream
    device.resume(pid)
    
    # Keep the script channel alive
    sys.stdin.read()

except Exception as e:
    print(f"[-] Critical Instrumentation Failure: {str(e)}")
