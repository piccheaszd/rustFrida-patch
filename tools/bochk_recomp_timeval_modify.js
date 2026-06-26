// BOCHK low-impact RECOMP modification probe.
//
// This is intentionally not a business-function hook.  It modifies one
// gettimeofday() output field by one microsecond, once, then only observes.

(function () {
  var patched = false;
  var calls = 0;
  var logs = 0;
  var maxLogs = 8;

  function log(line) {
    console.log("[timeval-mod] " + line);
  }

  function pstr(v) {
    try {
      if (v === null || v === undefined) return "0x0";
      return String(v);
    } catch (_) {
      return "<ptr>";
    }
  }

  function i32(v) {
    try {
      if (v && typeof v.toInt32 === "function") return v.toInt32();
      return Number(BigInt.asIntN(32, BigInt(String(v))));
    } catch (_) {
      return 0;
    }
  }

  function find(symbol) {
    try {
      var a = Module.findExportByName(null, symbol);
      if (a) return a;
    } catch (_) {
    }
    try {
      return Module.findExportByName("libc.so", symbol);
    } catch (_) {
      return null;
    }
  }

  var addr = find("gettimeofday");
  if (!addr) {
    log("missing gettimeofday");
    return;
  }

  log("gettimeofday=" + addr);

  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.tv = args[0];
      calls++;
    },
    onLeave: function (retval) {
      var ret = i32(retval);
      if (logs < maxLogs) {
        logs++;
        log("leave call=" + calls + " ret=" + ret + " tv=" + pstr(this.tv));
      }
      if (patched || ret !== 0 || !this.tv || pstr(this.tv) === "0x0") return;

      try {
        // struct timeval on arm64: time_t tv_sec; suseconds_t tv_usec.
        var usecPtr = this.tv.add(8);
        var oldUsec = BigInt(Memory.readU64(usecPtr));
        var newUsec = oldUsec < 999999n ? oldUsec + 1n : oldUsec - 1n;
        Memory.writeU64(usecPtr, newUsec);
        patched = true;
        log("patched timeval.tv_usec " + oldUsec + " -> " + newUsec);
      } catch (e) {
        log("patch failed: " + String(e));
      }
    }
  }, Hook.RECOMP);

  log("hook installed mode=RECOMP target=gettimeofday");
})();
