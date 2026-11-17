// Second attacker simulation: hide a file the app CAN see (/system/bin/sh) through libc access(),
// to exercise the libc-vs-raw-syscall comparison (F159). Real root hiders do the same for su paths.
const addr = Module.findGlobalExportByName("access");
Interceptor.attach(addr, {
  onEnter(args) {
    const p = args[0].readCString();
    this.hide = p !== null && p.indexOf("/system/bin/sh") >= 0;
  },
  onLeave(ret) {
    if (this.hide) ret.replace(ptr(-1));
  },
});
console.log("hide_sh.js: access() hook installed");
