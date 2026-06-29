// BOCHK RegisterNatives observer, single libart JNI<false> candidate.
// Observation-only diagnostic: no class resolution, no arg/retval changes.

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

  function resolveTarget() {
    try {
      var syms = Module.enumerateSymbols("libart.so");
      for (var i = 0; i < syms.length; i++) {
        var name = String(syms[i].name || "");
        if (name.indexOf("JNIILb0EE15RegisterNatives") >= 0) {
          return { name: name, address: ptr(syms[i].address) };
        }
      }
    } catch (e) {
      console.log("[rn-lb0] enumerateSymbols failed: " + e);
    }

    var base = Module.findBaseAddress("libart.so");
    if (base === null) throw new Error("libart.so base not found");
    return { name: "libart:JniFalse+fallback", address: base.add(0x3ff250) };
  }

  function describeAddress(addr) {
    try {
      var mod = Module.findByAddress(addr);
      if (mod === null) return { text: String(addr), module: null };
      return { text: mod.name + "+" + addr.sub(mod.base), module: mod.name };
    } catch (_) {
      return { text: String(addr), module: null };
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

  function onRegisterNatives(args) {
    calls++;
    var count = 0;
    try {
      count = Number(args[3]);
    } catch (_) {
      count = 0;
    }
    console.log("[rn-lb0] call=" + calls + " count=" + count);
    if (calls > maxCalls || count <= 0 || seenMethods >= maxMethods) return;

    var limit = count;
    if (seenMethods + limit > maxMethods) limit = maxMethods - seenMethods;

    for (var i = 0; i < limit; i++) {
      try {
        var method = readMethod(args[2], i);
        var where = describeAddress(method.fnPtr);
        if (where.module === "libbochk_aos.so") {
          console.log("[rn-lb0]   " + method.name + " " + method.sig + " -> " + where.text);
          seenMethods++;
        }
      } catch (e) {
        console.log("[rn-lb0] read method[" + i + "] failed: " + e);
      }
    }
  }

  var target = resolveTarget();
  console.log("[rn-lb0] target=" + target.name + " @ " + target.address);
  Interceptor.attach(target.address, { onEnter: onRegisterNatives }, Hook.RECOMP);
  console.log("[rn-lb0] hook installed mode=RECOMP");
})();
