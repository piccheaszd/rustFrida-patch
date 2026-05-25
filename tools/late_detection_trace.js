(function () {
    "use strict";

    var MAX_PER_KEY = 160;
    var counts = Object.create(null);
    var wxPages = Object.create(null);
    var installed = 0;
    var skipped = 0;
    var failed = 0;

    var NORMAL = (typeof Hook !== "undefined" && Hook.NORMAL !== undefined) ? Hook.NORMAL : 0;
    var WX = (typeof Hook !== "undefined" && Hook.WXSHADOW !== undefined) ? Hook.WXSHADOW : 1;

    function log(line) {
        console.log("[late-detect] " + line);
    }

    function hit(key) {
        var n = counts[key] || 0;
        if (n >= MAX_PER_KEY) return false;
        counts[key] = n + 1;
        if (n + 1 === MAX_PER_KEY) log(key + " limit reached");
        return true;
    }

    function u64(v) {
        try {
            if (v === null || v === undefined) return 0n;
            if (typeof v === "bigint") return v;
            if (typeof v === "number") return BigInt(Math.trunc(v));
            if (typeof v === "string") return BigInt(v);
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
        } catch (e) {
            return "<read-error:" + String(e) + ">";
        }
    }

    function moduleNameFromPath(path) {
        if (!path) return "";
        var i = path.lastIndexOf("/");
        return i >= 0 ? path.substring(i + 1) : path;
    }

    function moduleInfo(addr) {
        try {
            if (typeof Process === "undefined" || !Process.findModuleByAddress) return "";
            var m = Process.findModuleByAddress(addr);
            if (!m) return "";
            var off = u64(addr) - u64(m.base);
            return " mod=" + m.name + "+0x" + off.toString(16);
        } catch (_) {
            return "";
        }
    }

    function lr(ctx) {
        var ra = ctx.returnAddress || ctx.lr || ctx.x30;
        return pstr(ra) + moduleInfo(ra);
    }

    function logModuleByPath(path) {
        try {
            if (typeof Process === "undefined" || !Process.findModuleByName) return;
            var name = moduleNameFromPath(path);
            if (!name) return;
            var m = Process.findModuleByName(name);
            if (!m) return;
            log("module " + name + " base=" + pstr(m.base) + " size=0x" + u64(m.size).toString(16) + " path=" + m.path);
        } catch (_) {
        }
    }

    function hexByte(n) {
        return (n < 16 ? "0" : "") + n.toString(16);
    }

    function byteString(ptrValue, len) {
        try {
            var n = Number(len);
            if (n <= 0) return "";
            if (n > 512) n = 512;
            var bytes = new Uint8Array(Memory.readByteArray(ptrValue, n));
            var out = "";
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i];
                if (b >= 32 && b < 127) out += String.fromCharCode(b);
                else out += "\\x" + hexByte(b);
            }
            if (Number(len) > n) out += "...";
            return out;
        } catch (e) {
            return "<read-error:" + String(e) + ">";
        }
    }

    function pageOf(addr) {
        return "0x" + (u64(addr) & ~0xfffn).toString(16);
    }

    function modeName(mode) {
        if (mode === WX) return "WX";
        if (mode === NORMAL) return "NORMAL";
        return String(mode);
    }

    function find(symbol) {
        var libs = [null, "libc.so", "libdl.so", "liblog.so", "linker64", "linker"];
        for (var i = 0; i < libs.length; i++) {
            try {
                var a = Module.findExportByName(libs[i], symbol);
                if (a) return a;
            } catch (_) {
            }
        }
        return null;
    }

    function attach(symbol, callbacks, mode) {
        var addr = find(symbol);
        if (!addr) {
            log("missing " + symbol);
            return false;
        }

        var selected = (mode === undefined || mode === null) ? WX : mode;
        if (selected === WX) {
            var page = pageOf(addr);
            if (wxPages[page]) {
                skipped++;
                log("skip " + symbol + " mode=WX page-busy owner=" + wxPages[page] + " page=" + page);
                return false;
            }
            wxPages[page] = symbol;
        }

        try {
            Interceptor.attach(addr, callbacks, selected);
            installed++;
            log("hooked " + symbol + " mode=" + modeName(selected) + " addr=" + pstr(addr));
            return true;
        } catch (e) {
            failed++;
            log("hook failed " + symbol + " mode=" + modeName(selected) + " err=" + String(e));
            return false;
        }
    }

    function interestingPath(path) {
        if (!path) return true;
        return path.indexOf("/proc/") >= 0 ||
            path.indexOf("/fd/") >= 0 ||
            path.indexOf("/task/") >= 0 ||
            path.indexOf("maps") >= 0 ||
            path.indexOf("cmdline") >= 0 ||
            path.indexOf("status") >= 0 ||
            path.indexOf("mountinfo") >= 0 ||
            path.indexOf("pagemap") >= 0 ||
            path.indexOf("/mem") >= 0 ||
            path.indexOf(".so") >= 0 ||
            path.indexOf(".dex") >= 0 ||
            path.indexOf(".apk") >= 0 ||
            path.indexOf(".enc") >= 0 ||
            path.indexOf("res.data") >= 0 ||
            path.indexOf("enc.mf") >= 0 ||
            path.indexOf("xposed") >= 0 ||
            path.indexOf("Xposed") >= 0 ||
            path.indexOf("frida") >= 0 ||
            path.indexOf("agent") >= 0 ||
            path.indexOf("memfd") >= 0;
    }

    function prctlName(opt) {
        var n = Number(opt);
        if (n === 3) return "PR_GET_DUMPABLE";
        if (n === 4) return "PR_SET_DUMPABLE";
        if (n === 15) return "PR_SET_NAME";
        if (n === 16) return "PR_GET_NAME";
        if (n === 22) return "PR_SET_SECCOMP";
        if (n === 38) return "PR_SET_NO_NEW_PRIVS";
        if (n === 0x53564d41) return "PR_SET_VMA";
        if (n === 0x57580006) return "WX_PATCH";
        if (n === 0x57580008) return "WX_RELEASE";
        return String(n);
    }

    function logFdLink(fd, label) {
        if (fd < 3 || fd > 2048) return;
        try {
            var path = "/proc/self/fd/" + fd;
            var target = (typeof File !== "undefined" && File.readlink) ? File.readlink(path) : "";
            log(label + " fd=" + fd + " -> " + target);
        } catch (_) {
        }
    }

    attach("prctl", {
        onEnter: function (args) {
            this.opt = u64(args[0]);
            this.show = hit("prctl");
            if (this.show) {
                log("enter prctl opt=" + prctlName(this.opt) +
                    " raw=" + pstr(args[0]) + " a2=" + pstr(args[1]) +
                    " a3=" + pstr(args[2]) + " lr=" + lr(this));
            }
        },
        onLeave: function (retval) {
            if (this.show) log("leave prctl opt=" + prctlName(this.opt) + " ret=" + i32(retval));
        }
    }, NORMAL);

    attach("ptrace", {
        onEnter: function (args) {
            this.show = hit("ptrace");
            if (this.show) {
                log("enter ptrace req=" + pstr(args[0]) + " pid=" + i32(args[1]) +
                    " addr=" + pstr(args[2]) + " data=" + pstr(args[3]) + " lr=" + lr(this));
            }
        },
        onLeave: function (retval) {
            if (this.show) log("leave ptrace ret=" + i32(retval));
        }
    });

    attach("readlink", {
        onEnter: function (args) {
            this.path = cstr(args[0]);
            this.buf = args[1];
            this.show = interestingPath(this.path) && hit("readlink");
            if (this.show) log("enter readlink path=" + this.path + " size=" + pstr(args[2]) + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) {
                var ret = i32(retval);
                var target = ret > 0 ? " target=" + byteString(this.buf, ret) : "";
                log("leave readlink path=" + this.path + " ret=" + ret + target);
            }
        }
    });

    attach("readlinkat", {
        onEnter: function (args) {
            this.path = cstr(args[1]);
            this.buf = args[2];
            this.show = interestingPath(this.path) && hit("readlinkat");
            if (this.show) log("enter readlinkat dirfd=" + i32(args[0]) + " path=" + this.path + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) {
                var ret = i32(retval);
                var target = ret > 0 ? " target=" + byteString(this.buf, ret) : "";
                log("leave readlinkat path=" + this.path + " ret=" + ret + target);
            }
        }
    });

    attach("openat", {
        onEnter: function (args) {
            this.path = cstr(args[1]);
            this.show = interestingPath(this.path) && hit("openat");
            if (this.show) {
                log("enter openat dirfd=" + i32(args[0]) + " path=" + this.path +
                    " flags=" + pstr(args[2]) + " lr=" + lr(this));
            }
        },
        onLeave: function (retval) {
            if (this.show) log("leave openat path=" + this.path + " ret=" + i32(retval));
        }
    });

    attach("fopen", {
        onEnter: function (args) {
            this.path = cstr(args[0]);
            this.mode = cstr(args[1]);
            this.show = interestingPath(this.path) && hit("fopen");
            if (this.show) log("enter fopen path=" + this.path + " mode=" + this.mode + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) log("leave fopen path=" + this.path + " ret=" + pstr(retval));
        }
    });

    attach("close", {
        onEnter: function (args) {
            this.fd = i32(args[0]);
            this.show = this.fd >= 3 && hit("close");
            if (this.show) {
                log("enter close fd=" + this.fd + " lr=" + lr(this));
                logFdLink(this.fd, "close-target");
            }
        },
        onLeave: function (retval) {
            if (this.show) log("leave close fd=" + this.fd + " ret=" + i32(retval));
        }
    });

    attach("shutdown", {
        onEnter: function (args) {
            this.fd = i32(args[0]);
            this.how = i32(args[1]);
            this.show = this.fd >= 3 && hit("shutdown");
            if (this.show) log("enter shutdown fd=" + this.fd + " how=" + this.how + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) log("leave shutdown fd=" + this.fd + " ret=" + i32(retval));
        }
    });

    attach("kill", {
        onEnter: function (args) {
            this.show = hit("kill");
            if (this.show) log("enter kill pid=" + i32(args[0]) + " sig=" + i32(args[1]) + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) log("leave kill ret=" + i32(retval));
        }
    });

    attach("tgkill", {
        onEnter: function (args) {
            this.show = hit("tgkill");
            if (this.show) log("enter tgkill tgid=" + i32(args[0]) + " tid=" + i32(args[1]) + " sig=" + i32(args[2]) + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) log("leave tgkill ret=" + i32(retval));
        }
    });

    attach("abort", {
        onEnter: function () {
            if (hit("abort")) log("enter abort lr=" + lr(this));
        }
    });

    attach("exit", {
        onEnter: function (args) {
            if (hit("exit")) log("enter exit code=" + i32(args[0]) + " lr=" + lr(this));
        }
    });

    attach("_exit", {
        onEnter: function (args) {
            if (hit("_exit")) log("enter _exit code=" + i32(args[0]) + " lr=" + lr(this));
        }
    });

    attach("android_dlopen_ext", {
        onEnter: function (args) {
            this.path = cstr(args[0]);
            this.show = interestingPath(this.path) && hit("android_dlopen_ext");
            if (this.show) log("enter android_dlopen_ext path=" + this.path + " flags=" + pstr(args[1]) + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) {
                log("leave android_dlopen_ext path=" + this.path + " ret=" + pstr(retval));
                logModuleByPath(this.path);
            }
        }
    });

    attach("dlopen", {
        onEnter: function (args) {
            this.path = cstr(args[0]);
            this.show = interestingPath(this.path) && hit("dlopen");
            if (this.show) log("enter dlopen path=" + this.path + " flags=" + pstr(args[1]) + " lr=" + lr(this));
        },
        onLeave: function (retval) {
            if (this.show) {
                log("leave dlopen path=" + this.path + " ret=" + pstr(retval));
                logModuleByPath(this.path);
            }
        }
    });

    log("ready installed=" + installed + " skipped=" + skipped + " failed=" + failed);
})();
