// BOCHK business native boolean observe-only probe.
//
// Flow:
// - hook only libart JNI<false>::RegisterNatives with Hook.RECOMP
// - locate kmv.ar.d()Z in libbochk_aos.so
// - hook that native method with Hook.RECOMP
// - log hits and return values only

(function () {
  "use strict";

  var POINTER_SIZE = 8;
  var targetClass = "kmv.ar";
  var targetName = "d";
  var targetSig = "()Z";
  var targetOffset = "0x238ec0";

  var rnCalls = 0;
  var targetInstalling = false;
  var targetHooked = false;
  var targetHits = 0;
  var logs = 0;
  var maxLogs = 16;

  function log(line) {
    console.log("[biz-observe] " + line);
  }

  function safeString(value, fallback) {
    try {
      if (value === null || value === undefined) return fallback;
      var s = String(value);
      return s.length === 0 ? fallback : s;
    } catch (_) {
      return fallback;
    }
  }

  function pstr(v) {
    try {
      if (v === null || v === undefined) return "0x0";
      return String(v);
    } catch (_) {
      return "<ptr>";
    }
  }

  function describeAddress(addr) {
    try {
      var mod = Module.findByAddress(addr);
      if (mod === null) return { text: pstr(addr), module: null, offset: null };
      return {
        text: mod.name + "+" + addr.sub(mod.base),
        module: mod.name,
        offset: String(addr.sub(mod.base))
      };
    } catch (_) {
      return { text: pstr(addr), module: null, offset: null };
    }
  }

  function resolveRegisterNativesTarget() {
    try {
      var syms = Module.enumerateSymbols("libart.so");
      for (var i = 0; i < syms.length; i++) {
        var name = String(syms[i].name || "");
        if (name.indexOf("JNIILb0EE15RegisterNatives") >= 0) {
          return ptr(syms[i].address);
        }
      }
    } catch (e) {
      log("enumerateSymbols failed: " + String(e));
    }

    var base = Module.findBaseAddress("libart.so");
    if (base === null) throw new Error("libart.so base not found");
    return base.add(0x3ff250);
  }

  function classNameFromEnv(env, clazz) {
    try {
      return safeString(Jni.env.getClassName(env, clazz), "<class-null>");
    } catch (e) {
      return "<class-error:" + e + ">";
    }
  }

  function readMethod(methods, index) {
    var base = ptr(methods).add(index * POINTER_SIZE * 3);
    var namePtr = Memory.readPointer(base);
    var sigPtr = Memory.readPointer(base.add(POINTER_SIZE));
    var fnPtr = Memory.readPointer(base.add(POINTER_SIZE * 2));
    return {
      name: namePtr.toString() === "0x0" ? "<null>" : safeString(Memory.readCString(namePtr), "<name-error>"),
      sig: sigPtr.toString() === "0x0" ? "<null>" : safeString(Memory.readCString(sigPtr), "<sig-error>"),
      fnPtr: fnPtr
    };
  }

  function retBool(retval) {
    try {
      return retval.toUInt32() & 1;
    } catch (_) {
      return -1;
    }
  }

  function installBusinessHook(addr, where) {
    if (targetHooked || targetInstalling) return;
    targetInstalling = true;
    log("install target " + targetClass + "." + targetName + targetSig + " at " + describeAddress(addr).text + " from " + where);

    try {
      Interceptor.attach(addr, {
        onEnter: function () {
          targetHits++;
          if (logs < maxLogs) {
            logs++;
            log("enter hit=" + targetHits + " lr=" + pstr(this.returnAddress || this.lr || this.x30));
          }
        },
        onLeave: function (retval) {
          if (logs < maxLogs) {
            logs++;
            log("leave hit=" + targetHits + " ret=" + retBool(retval));
          }
        }
      }, Hook.RECOMP);
      targetHooked = true;
      log("target hook installed mode=RECOMP");
    } catch (e) {
      log("target hook failed: " + String(e));
    } finally {
      targetInstalling = false;
    }
  }

  log("start target=" + targetClass + "." + targetName + targetSig + " expectedOffset=" + targetOffset);
  var registerNatives = resolveRegisterNativesTarget();
  log("RegisterNatives=" + registerNatives);

  Interceptor.attach(registerNatives, {
    onEnter: function (args) {
      rnCalls++;
      if (targetHooked) return;

      var clazz = classNameFromEnv(args[0], args[1]);
      if (clazz !== targetClass) return;

      var count = 0;
      try {
        count = Number(args[3]);
      } catch (_) {
        count = 0;
      }
      if (count <= 0) return;

      log("RegisterNatives target class call=" + rnCalls + " count=" + count);

      for (var i = 0; i < count; i++) {
        try {
          var method = readMethod(args[2], i);
          var where = describeAddress(method.fnPtr);
          log("  method " + method.name + " " + method.sig + " -> " + where.text);
          if (method.name === targetName && method.sig === targetSig && where.module === "libbochk_aos.so") {
            installBusinessHook(method.fnPtr, "RegisterNatives.onEnter");
          }
        } catch (e) {
          log("read method[" + i + "] failed: " + String(e));
        }
      }
    }
  }, Hook.RECOMP);

  log("RegisterNatives hook installed mode=RECOMP");
})();
