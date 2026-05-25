(function () {
    "use strict";

    var MAX_LOG = 96;
    var counts = Object.create(null);
    var active = false;
    var NORMAL = (typeof Hook !== "undefined" && Hook.NORMAL !== undefined) ? Hook.NORMAL : 0;
    var WX = (typeof Hook !== "undefined" && Hook.WXSHADOW !== undefined) ? Hook.WXSHADOW : 1;

    function log(line) {
        console.log("[early-pid-guard] " + line);
    }

    function hit(key) {
        var n = counts[key] || 0;
        if (n >= MAX_LOG) return false;
        counts[key] = n + 1;
        if (n + 1 === MAX_LOG) log(key + " limit reached");
        return true;
    }

    function u64(v) {
        try {
            if (v === null || v === undefined) return 0n;
            if (typeof v === "bigint") return v;
            if (typeof v === "number") return BigInt(Math.trunc(v));
            return BigInt(String(v));
        } catch (_) {
            return 0n;
        }
    }

    function i32(v) {
        try {
            if (v && typeof v.toInt32 === "function") return v.toInt32();
            return Number(BigInt.asIntN(32, u64(v)));
        } catch (_) {
            return 0;
        }
    }

    function pstr(v) {
        try {
            if (v === null || v === undefined) return "0x0";
            if (typeof v === "bigint") return "0x" + v.toString(16);
            if (typeof v === "number") return "0x" + BigInt(Math.trunc(v)).toString(16);
            return String(v);
        } catch (_) {
            return "<ptr>";
        }
    }

    function cstr(v) {
        try {
            if (!v) return "";
            if (typeof v.readCString === "function") return v.readCString();
            return Memory.readCString(v);
        } catch (_) {
            return "";
        }
    }

    function lr(ctx) {
        return pstr(ctx.returnAddress || ctx.lr || ctx.x30);
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

    function attach(symbol, callbacks, mode) {
        var addr = find(symbol);
        if (!addr) {
            log("missing " + symbol);
            return false;
        }
        try {
            Interceptor.attach(addr, callbacks, mode === undefined ? WX : mode);
            log("hooked " + symbol + " addr=" + pstr(addr));
            return true;
        } catch (e) {
            log("hook failed " + symbol + " err=" + String(e));
            return false;
        }
    }

    function suspiciousLink(s) {
        if (!s) return false;
        var lower = String(s).toLowerCase();
        return lower.indexOf("memfd") >= 0 ||
            lower.indexOf("rustfrida") >= 0 ||
            lower.indexOf("frida") >= 0 ||
            lower.indexOf("gum") >= 0 ||
            lower.indexOf("loader") >= 0 ||
            lower.indexOf("agent") >= 0;
    }

    function readBytesText(ptrValue, len) {
        try {
            var n = Number(len);
            if (n <= 0) return "";
            if (n > 512) n = 512;
            var bytes = new Uint8Array(Memory.readByteArray(ptrValue, n));
            var out = "";
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i];
                if (b >= 32 && b < 127) out += String.fromCharCode(b);
                else if (b === 0) break;
                else out += ".";
            }
            return out;
        } catch (_) {
            return "";
        }
    }

    function writeCString(buf, cap, text) {
        try {
            var max = Number(cap);
            if (!buf || max <= 1) return 0;
            var out = String(text);
            if (out.length >= max) out = out.slice(0, max - 1);
            if (typeof buf.writeUtf8String === "function") {
                buf.writeUtf8String(out);
            } else {
                Memory.writeUtf8String(buf, out);
            }
            return out.length;
        } catch (e) {
            log("writeCString failed: " + String(e));
            return 0;
        }
    }

    // prctl is used by the hook backend itself, so keep this hook non-WX and
    // install it before WX hooks touch libc pages.
    attach("prctl", {
        onEnter: function (args) {
            this.opt = Number(u64(args[0]));
            this.show = this.opt === 3 || this.opt === 4 || this.opt === 15 || this.opt === 16;
            if (this.show && hit("prctl")) log("prctl opt=" + this.opt + " a2=" + pstr(args[1]) + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (active && this.opt === 3) {
                retval.replace(0);
                if (hit("dumpable_mask")) log("PR_GET_DUMPABLE masked to 0");
            }
        }
    }, NORMAL);

    attach("ptrace", {
        onEnter: function (args) {
            this.req = Number(u64(args[0]));
            if (hit("ptrace")) log("ptrace req=" + this.req + " pid=" + i32(args[1]) + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (active && this.req === 0) {
                retval.replace(0);
                if (hit("ptrace_mask")) log("PTRACE_TRACEME masked to success");
            }
        }
    });

    attach("readlink", {
        onEnter: function (args) {
            this.path = cstr(args[0]);
            this.buf = args[1];
            this.size = Number(u64(args[2]));
            this.show = this.path.indexOf("/proc/self/fd/") === 0 || this.path.indexOf("/proc/") === 0;
            if (this.show && hit("readlink")) log("readlink enter path=" + this.path + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            var n = i32(retval);
            if (n <= 0 || !this.buf) return;
            var target = readBytesText(this.buf, n);
            if (this.show && hit("readlink_ret")) log("readlink leave path=" + this.path + " ret=" + n + " target=" + target);
            if (active && this.path.indexOf("/proc/self/fd/") === 0 && suspiciousLink(target)) {
                var len = writeCString(this.buf, this.size, "/dev/null");
                if (len > 0) {
                    retval.replace(len);
                    if (hit("readlink_mask")) log("readlink masked path=" + this.path + " old=" + target);
                }
            }
        }
    });

    attach("readlinkat", {
        onEnter: function (args) {
            this.path = cstr(args[1]);
            this.buf = args[2];
            this.size = Number(u64(args[3]));
            this.show = this.path.indexOf("/proc/self/fd/") === 0 || this.path.indexOf("/proc/") === 0;
            if (this.show && hit("readlinkat")) log("readlinkat enter path=" + this.path + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            var n = i32(retval);
            if (n <= 0 || !this.buf) return;
            var target = readBytesText(this.buf, n);
            if (active && this.path.indexOf("/proc/self/fd/") === 0 && suspiciousLink(target)) {
                var len = writeCString(this.buf, this.size, "/dev/null");
                if (len > 0) {
                    retval.replace(len);
                    if (hit("readlinkat_mask")) log("readlinkat masked path=" + this.path + " old=" + target);
                }
            }
        }
    });

    attach("fopen", {
        onEnter: function (args) {
            this.path = cstr(args[0]);
            if ((this.path.indexOf("/proc/self/maps") === 0 ||
                this.path.indexOf("/proc/") === 0 && (this.path.indexOf("/status") >= 0 || this.path.indexOf("/cmdline") >= 0)) &&
                hit("fopen")) {
                log("fopen path=" + this.path + " lr=" + lr(this));
            }
        }
    });

    attach("openat", {
        onEnter: function (args) {
            this.path = cstr(args[1]);
            if ((this.path.indexOf("/proc/self/task/") === 0 ||
                this.path.indexOf("/proc/self/maps") === 0 ||
                this.path.indexOf("/proc/") === 0 && (this.path.indexOf("/status") >= 0 || this.path.indexOf("/cmdline") >= 0)) &&
                hit("openat")) {
                log("openat path=" + this.path + " lr=" + lr(this));
            }
        }
    });

    active = true;
    log("ready maxLog=" + MAX_LOG);
})();
