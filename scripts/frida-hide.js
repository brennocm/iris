// Frida script for the instrumentation scenario (docs/scenarios.md).
// It does what common "Frida bypass" scripts do: hooks libc so reads of /proc/self/maps hide
// frida lines, and makes strstr() never match "frida". Iris reads /proc with raw syscalls, so
// these hooks never see its reads and HOOK-001 / HOOK-002 still fire; the hooks themselves
// are what HOOK-004 reports.
const libc = Process.getModuleByName("libc.so");
let hidden = 0;

Interceptor.attach(libc.getExportByName("strstr"), {
  onEnter(args) { this.needle = args[1].readCString(); },
  onLeave(ret) { if (this.needle && this.needle.includes("frida")) { ret.replace(ptr(0)); hidden++; } },
});

const fds = new Set();
Interceptor.attach(libc.getExportByName("openat"), {
  onEnter(args) { this.path = args[1].readCString(); },
  onLeave(ret) { if (this.path && this.path.endsWith("/maps") && ret.toInt32() >= 0) fds.add(ret.toInt32()); },
});
Interceptor.attach(libc.getExportByName("read"), {
  onEnter(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
  onLeave(ret) {
    const n = ret.toInt32();
    if (!fds.has(this.fd) || n <= 0) return;
    const text = this.buf.readUtf8String(n);
    if (!text.includes("frida")) return;
    const clean = text.split("\n").map(l => l.includes("frida") ? "" : l).join("\n");
    this.buf.writeUtf8String(clean.padEnd(n, " ").slice(0, n));
    hidden++;
  },
});
console.log("iris-scenario: libc hooks installed");
