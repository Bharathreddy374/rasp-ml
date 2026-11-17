// Attacker simulation for testing the trust probes (Frida 17, injected with frida-inject).
// Classic root hiding: inline-hook libc file checks so su / Magisk paths look absent.
const HIDE = ["/su", "xbin/su", "bin/su", "magisk", "/data/adb/"];
const FAIL = { access: ptr(-1), stat: ptr(-1), open: ptr(-1), fopen: ptr(0) };

for (const name of Object.keys(FAIL)) {
  const addr = Module.findGlobalExportByName(name);
  if (addr === null) continue;
  Interceptor.attach(addr, {
    onEnter(args) {
      const p = args[0].readCString();
      this.hide = p !== null && HIDE.some(h => p.indexOf(h) >= 0);
    },
    onLeave(ret) {
      if (this.hide) ret.replace(FAIL[name]);
    },
  });
}
console.log("hide_root.js: hooks installed");
