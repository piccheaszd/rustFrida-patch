// BOCHK RegisterNatives observer using native libart resolution.
//
// Observation-only:
// - avoids Jni.addr("RegisterNatives") before resume
// - hooks the libart JNI<false> RegisterNatives candidate with Hook.RECOMP
// - logs class, method name, signature, and libbochk_aos.so offset
// - does not change arguments or return values

(function () {
  "use strict";

  var POINTER_SIZE = 8;
  var maxCalls = 32;
  var maxMethods = 180;
  var calls = 0;
  var seenMethods = 0;

  function safeString(value, fallback) {
    try {
      if (value === null || value === undefined) return fallback;
      var s = String(value);
      return s.length === 0 ? fallback : s;
    } catch (_) {
      return fallback;
    }
  }

  function ptrKey(value) {
    try {
      return ptr(value).toString();
    } catch (_) {
      return String(value);
    }
  }

  function isNullPtr(value) {
    try {
      return ptr(value).toString() === "0x0";
    } catch (_) {
      return true;
    }
  }

  function addCandidate(out, seen, name, address) {
    if (address === null || address === undefined || isNullPtr(address)) return;
    var key = ptrKey(address);
    if (seen[key]) return;
    seen[key] = true;
    out.push({ name: name, address: ptr(address) });
  }

  function resolveRegisterNativesTarget() {
    var out = [];
    var seen = Object.create(null);

    try {
      var syms = Module.enumerateSymbols("libart.so");
      for (var i = 0; i < syms.length; i++) {
        var name = String(syms[i].name || "");
        if (name.indexOf("RegisterNatives") < 0) continue;
        if (name.indexOf("JNIILb0EE15RegisterNatives") >= 0) {
          addCandidate(out, seen, "libart:JniFalse", syms[i].address);
          break;
        }
      }
    } catch (e) {
      console.log("[rn-native] enumerateSymbols failed: " + e);
    }

    if (out.length === 0) {
      try {
        var base = Module.findBaseAddress("libart.so");
        if (base !== null) {
          addCandidate(out, seen, "libart:JniFalse+fallback", base.add(0x3ff250));
        }
      } catch (fallbackError) {
        console.log("[rn-native] fallback failed: " + fallbackError);
      }
    }

    if (out.length === 0) {
      throw new Error("RegisterNatives JNI<false> target not found");
    }
    return out[0];
  }

  function describeAddress(addr) {
    try {
      var mod = Module.findByAddress(addr);
      if (mod === null) return { text: String(addr), module: null, offset: null };
      return {
        text: mod.name + "+" + addr.sub(mod.base),
        module: mod.name,
        offset: addr.sub(mod.base)
      };
    } catch (e) {
      return { text: String(addr), module: null, offset: null };
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

  function classNameFromEnv(env, clazz) {
    try {
      return safeString(Jni.env.getClassName(env, clazz), "<class-null>");
    } catch (e) {
      return "<class-error:" + e + ">";
    }
  }

  function onRegisterNatives(args) {
    calls++;
    var env = args[0];
    var clazz = args[1];
    var methods = args[2];
    var count = 0;
    try {
      count = Number(args[3]);
    } catch (_) {
      count = 0;
    }

    var cls = classNameFromEnv(env, clazz);
    console.log("[rn-native] call=" + calls + " class=" + cls + " count=" + count);

    if (calls > maxCalls || count <= 0 || seenMethods >= maxMethods) return;

    var limit = count;
    if (seenMethods + limit > maxMethods) limit = maxMethods - seenMethods;

    var skipped = 0;
    for (var i = 0; i < limit; i++) {
      try {
        var method = readMethod(methods, i);
        var where = describeAddress(method.fnPtr);
        if (where.module === "libbochk_aos.so") {
          console.log("[rn-native]   " + cls + " " + method.name + " " + method.sig + " -> " + where.text);
          seenMethods++;
        } else {
          skipped++;
        }
      } catch (e) {
        console.log("[rn-native] read method[" + i + "] failed: " + e);
      }
    }
    if (skipped > 0) {
      console.log("[rn-native]   skipped-non-bochk=" + skipped);
    }
  }

  var target = resolveRegisterNativesTarget();
  console.log("[rn-native] target " + target.name + "=" + target.address);
  Interceptor.attach(target.address, { onEnter: onRegisterNatives }, Hook.RECOMP);
  console.log("[rn-native] hooks installed mode=RECOMP maxMethods=" + maxMethods + " maxCalls=" + maxCalls);
})();
