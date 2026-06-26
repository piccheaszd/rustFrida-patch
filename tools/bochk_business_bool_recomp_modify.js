// BOCHK business native boolean modification probe.
//
// Flow:
// 1. Hook JNIEnv->RegisterNatives with Hook.RECOMP.
// 2. Find fiqlohqeo.ap.d()Z as it is registered by BOCHK.
// 3. Hook that libbochk_aos.so native function with Hook.RECOMP.
// 4. Flip its boolean return once, then only observe.

(function () {
  var targetClass = "fiqlohqeo.ap";
  var targetName = "d";
  var targetSig = "()Z";

  var rnCalls = 0;
  var targetInstalling = false;
  var targetHooked = false;
  var targetHits = 0;
  var flipped = false;
  var logs = 0;
  var maxLogs = 16;

  function log(line) {
    console.log("[biz-bool] " + line);
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
      if (mod === null) return pstr(addr);
      return mod.name + "+" + addr.sub(mod.base);
    } catch (_) {
      return pstr(addr);
    }
  }

  function installBusinessHook(addr, where) {
    if (targetHooked || targetInstalling) return;
    targetInstalling = true;
    log("install target " + targetClass + "." + targetName + targetSig + " at " + describeAddress(addr) + " from " + where);

    try {
      Interceptor.attach(addr, {
        onEnter: function () {
          targetHits++;
          if (logs < maxLogs) {
            logs++;
            log("enter target hit=" + targetHits + " lr=" + pstr(this.returnAddress || this.lr || this.x30));
          }
        },
        onLeave: function (retval) {
          var raw = 0;
          try {
            raw = retval.toUInt32() & 1;
          } catch (_) {
            raw = 0;
          }
          if (!flipped) {
            var replacement = raw ? 0 : 1;
            retval.replace(replacement);
            flipped = true;
            log("flipped return " + raw + " -> " + replacement + " hit=" + targetHits);
          } else if (logs < maxLogs) {
            logs++;
            log("leave target ret=" + raw + " hit=" + targetHits);
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

  log("start target=" + targetClass + "." + targetName + targetSig);
  var registerNatives = Jni.addr("RegisterNatives");
  log("RegisterNatives=" + registerNatives);

  Interceptor.attach(registerNatives, {
    onEnter: function (args) {
      rnCalls++;
      this.target = null;

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

      if (clazz !== targetClass || count <= 0 || targetHooked) return;
      log("RegisterNatives target class call=" + rnCalls + " count=" + count);

      try {
        var methods = Jni.structs.JNINativeMethod.readArray(args[2], count);
        for (var i = 0; i < methods.length; i++) {
          var name = safeString(methods[i].name, "<null>");
          var sig = safeString(methods[i].sig, "<null>");
          var fnPtr = methods[i].fnPtr;
          log("  method " + name + " " + sig + " -> " + describeAddress(fnPtr));
          if (name === targetName && sig === targetSig) {
            this.target = fnPtr;
            installBusinessHook(fnPtr, "RegisterNatives.onEnter");
          }
        }
      } catch (e) {
        log("readArray failed: " + String(e));
      }
    }
  }, Hook.RECOMP);

  log("RegisterNatives hook installed mode=RECOMP target=" + targetClass + "." + targetName + targetSig);
})();
