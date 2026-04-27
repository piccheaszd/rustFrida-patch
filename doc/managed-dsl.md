# Managed DSL

`Java.managedHookDsl` compiles hook logic into a generated dex helper and routes the
target method through the managed direct thunk. It is intended for high-frequency
Java method hooks where JS/Lua callbacks are too expensive or unstable under app
natural traffic.

## Basic Usage

```js
Java.ready(function () {
  Java.compileMethod(
    "java.util.HashMap",
    "put",
    "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    "auto"
  );

  Java._resetArtRouteStats();

  Java.managedHookDsl({
    className: "java.util.HashMap",
    methodName: "put",
    signature: "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    dsl:
      "let n: int = this.size.overload()();" +
      "let plus: int = n + 1;" +
      "let sb: java.lang.StringBuilder = java.lang.StringBuilder.$new(\"java.lang.String\", \"seed\");" +
      "sb.append.overload(\"java.lang.Object\")(arg0);" +
      "new int[](3);" +
      "let a: int[] = last;" +
      "a[0] = plus;" +
      "if (plus > 0) {" +
      "  return orig(arg0, arg1);" +
      "} else {" +
      "  return orig(arg0, arg1);" +
      "}"
  });
});
```

## High-Frequency Rules

If a DSL program uses `orig()`, every return path must end with `return orig();`
or `return orig(...)`.
The compiler rejects mixed return paths such as:

```js
"if (arg0 == null) {" +
"  return null;" +
"} else {" +
"  return orig();" +
"}"
```

This restriction is deliberate. The managed direct thunk arms the per-thread
orig bypass before entering the generated helper. Requiring every return path to
consume that bypass prevents leaked bypass slots on high-frequency traffic.

`orig()` calls the original method with the original receiver and arguments.
`orig(arg0, arg1)` calls the original method with explicit replacement
arguments. The replacement argument count must exactly match the hooked method's
parameter count; instance receivers are still supplied automatically.

The expected stable stats are:

```text
managed == orig == set
fail=0
active=0
backup=0
```

## Supported DSL Syntax

### Locals

```js
"let n: int = this.size.overload()();" +
"let plus: int = n + 1;"
```

Local declarations require an explicit type.

### Arguments And Built-In Targets

```text
this   current receiver, only for instance methods
arg0   first Java argument
arg1   second Java argument
last   last object result produced by new/call/cast/array get
result last primitive int-like result
```

Aliases such as `$this`, `$last`, `$0`, `$1`, `p0`, and `p1` are also accepted by
the parser, but the JS-like names above are preferred.

### Constructors

```js
"new java.lang.StringBuilder(\"java.lang.String\", \"seed\");"
```

Constructor expression:

```js
"let sb: java.lang.StringBuilder = java.lang.StringBuilder.$new(\"java.lang.String\", \"seed\");"
```

For no-arg constructors:

```js
"new java.lang.StringBuilder();"
```

The new object is stored in `last`.

Full JNI constructor signatures are still accepted as a fallback:

```js
"new java.lang.StringBuilder(\"(Ljava/lang/String;)V\", \"seed\");"
```

### Method Calls

Instance call with inferred receiver:

```js
"let sb: java.lang.StringBuilder = last;" +
"sb.append.overload(\"java.lang.Object\")(arg0);"
```

Instance call on `this`:

```js
"let n: int = this.size.overload()();"
```

Static call:

```js
"let value: int = java.lang.Integer.parseInt.overload(\"java.lang.String\")(\"123\");"
```

`overload(...)` accepts Java parameter type names. The return type is resolved
from reflection by class + method name + parameter list, because Java return
types do not participate in overload selection.

Full JNI signatures are still accepted when reflection cannot resolve a method:

```js
"last.append.overload(\"java.lang.StringBuilder\", \"(Ljava/lang/Object;)Ljava/lang/StringBuilder;\")(arg0);"
```

### Original Calls

Call the original method with unchanged arguments:

```js
"return orig();"
```

Call the original method with explicit arguments:

```js
"return orig(arg0, arg1);"
```

Store the original result before running more DSL logic:

```js
"let old: java.lang.Object = orig(arg0, arg1);" +
"return old;"
```

For instance hooks, do not pass `this` to `orig(...)`; only pass Java method
parameters. For static hooks, pass all static method parameters.

### Arrays

```js
"new int[](3);" +
"let a: int[] = last;" +
"let x: int = a[0];" +
"a[1] = x + 1;"
```

Array element type is inferred from local and argument descriptors. If inference
fails, use explicit element type syntax:

```js
"let x: int = a[0: int];"
```

### Fields

Field read and write use member syntax with an explicit field type:

```js
"let n: int = this.size(\"int\");" +
"this.size(\"int\") = n + 1;"
```

For ambiguous receiver types, include the declaring class:

```js
"let n: int = this.size(\"java.util.HashMap\", \"int\");"
```

### Conditions

```js
"if (arg0 == null) {" +
"  return orig();" +
"} else {" +
"  return orig();" +
"}"
```

Supported comparisons include `==`, `!=`, `<`, `<=`, `>`, and `>=`. `null`
conditions only support `==` and `!=`.

`instanceof` is supported:

```js
"if (arg0 instanceof java.lang.String) {" +
"  return orig();" +
"} else {" +
"  return orig();" +
"}"
```

Compound conditions support JS-like `&&`, `||`, `!`, and parentheses:

```js
"if ((arg0 != null && arg1 != null) || !(arg0 instanceof java.lang.String)) {" +
"  return orig();" +
"} else {" +
"  return orig();" +
"}"
```

Integer `switch` is supported with explicit blocks and automatic break:

```js
"switch (code) {" +
"  case 0: { return orig(); }" +
"  case 1: { return null; }" +
"  default: { return orig(); }" +
"}"
```

Dense integer cases compile to dex `packed-switch`; sparse cases compile to
dex `sparse-switch`.

### Returns

High-frequency orig path:

```js
"return orig();"
```

Orig result path:

```js
"let old: java.lang.Object = orig(arg0, arg1);" +
"return old;"
```

`let x = orig(...)` is intentionally restricted: it must appear once as the
first top-level statement, and it cannot be mixed with `return orig(...)`. This
keeps the per-thread orig bypass consumed exactly once before any user DSL logic
runs.

Direct value returns are supported only for DSL programs that do not use
`orig()` or `orig(...)`:

```js
"return null;"
"return 1;"
```

## Current Limits

- `return orig(...)` cannot be mixed with `return null`, `return value`, or
  fall-through return paths.
- `let x = orig(...)` must be the first top-level statement and cannot be nested.
- Local variable type inference is not supported; use `let name: Type = value`.
- `switch` supports integer case constants only. Case bodies must use `{ ... }`,
  and fallthrough/break are not part of the DSL.
- Loops are not part of the JS-like managed DSL.
- Try/catch, throw, monitor enter/exit, and synchronized blocks are not part of
  the DSL.
- Complex object lifetime rules should stay inside generated managed code.
  Avoid JS/Lua callbacks on hot methods.
- Reflection-style Java APIs from JS/Lua are not the high-frequency path. Use
  managed DSL operations that compile into dex bytecode.

## Device Validation

Build and push:

```bash
cargo build --release -p agent
cargo build --release -p rust_frida
adb -s <device> push target/aarch64-linux-android/release/rustfrida /data/local/tmp/rustfrida
adb -s <device> shell "su -c 'sh -c \"chmod 755 /data/local/tmp/rustfrida\"'"
```

Run a high-frequency validation script:

```bash
({ sleep 45; \
   echo 'jseval (function(){var s=Java._artRouteStats(); return "managed="+String(s.managedDirectHits)+",orig="+String(s.origBypassHits)+",set="+String(s.origBypassSetSuccesses)+",fail="+String(s.origBypassSetFailures)+",active="+String(s.origBypassActive)+",backup="+String(s.managedBackupStubHits);})()'; \
   sleep 3; echo exit; } | timeout 80s adb -s <device> shell \
  "su -c '/data/local/tmp/rustfrida --spawn com.jingdong.app.mall -l /data/local/tmp/test_js_accept_managed_dsl_ops_orig.js'")
```

Check logcat:

```bash
adb -s <device> logcat -d -v time | rg -i \
  "ANR|not responding|SuspendAll timeout|Fatal signal|SIGABRT|SIGSEGV|DynManagedHook|managedHook"
```

Successful validation should show the route stats closed:

```text
managed=354184,orig=354184,set=354184,fail=0,active=0,backup=0
```

The exact count varies with app traffic. The important conditions are equal
`managed`, `orig`, and `set` counts, zero failures, zero active bypass slots, no
backup stub hits, and no ANR/SuspendAll/SIGSEGV/fatal signal in logcat.

## Local Acceptance Scripts

The repository root may contain local, ignored manual scripts:

```text
test_js_accept_managed_dsl_orig_array.js
test_js_accept_managed_dsl_ops_orig.js
test_js_reject_managed_dsl_mixed_orig.js
```

They are intentionally excluded from commits by local git exclude rules because
repository policy does not commit test-related files by default.
