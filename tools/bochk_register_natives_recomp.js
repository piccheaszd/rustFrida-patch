// BOCHK RegisterNatives observer.
//
// Observation-only script:
// - hooks JNIEnv->RegisterNatives with Hook.RECOMP
// - logs class, method name, signature, native function address, and module
// - does not change arguments or return values

(function () {
  var maxMethods = 80;
  var seenMethods = 0;
  var calls = 0;

  function safeString(value, fallback) {
    try {
      if (value === null || value === undefined) return fallback;
      var s = String(value);
      return s.length === 0 ? fallback : s;
    } catch (_) {
      return fallback;
    }
  }

  function describeAddress(addr) {
    try {
      var mod = Module.findByAddress(addr);
      if (mod === null) return String(addr);
      return mod.name + "+" + addr.sub(mod.base);
    } catch (e) {
      return String(addr);
    }
  }

  function logMethod(method) {
    var name = safeString(method.name, "<null>");
    var sig = safeString(method.sig, "<null>");
    var where = describeAddress(method.fnPtr);
    console.log("[rn]   " + name + " " + sig + " -> " + where);
  }

  var registerNatives = Jni.addr("RegisterNatives");
  console.log("[rn] RegisterNatives=" + registerNatives);

  Interceptor.attach(registerNatives, {
    onEnter: function (args) {
      calls++;
      var clazz = "<class-error>";
      var count = 0;
      try {
        clazz = safeString(Jni.env.getClassName(args[1]), "<class-null>");
      } catch (e) {
        clazz = "<class-exception:" + e + ">";
      }

      try {
        count = Number(args[3]);
      } catch (_) {
        count = 0;
      }

      console.log("[rn] RegisterNatives call=" + calls + " class=" + clazz + " count=" + count);

      if (count <= 0 || seenMethods >= maxMethods) return;

      var limit = count;
      if (seenMethods + limit > maxMethods) limit = maxMethods - seenMethods;

      try {
        var methods = Jni.structs.JNINativeMethod.readArray(args[2], limit);
        for (var i = 0; i < methods.length; i++) {
          logMethod(methods[i]);
          seenMethods++;
        }
      } catch (e) {
        console.log("[rn] readArray failed: " + e);
      }
    }
  }, Hook.RECOMP);

  console.log("[rn] hook installed mode=RECOMP maxMethods=" + maxMethods);
})();
