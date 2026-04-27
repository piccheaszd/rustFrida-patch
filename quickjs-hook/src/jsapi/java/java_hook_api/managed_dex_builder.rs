use std::collections::BTreeSet;

use super::super::jni_core::JniEnv;
use super::super::reflect::{enumerate_methods, enumerate_methods_declared_only};

pub(super) const ACC_PUBLIC: u32 = 0x0001;
pub(super) const ACC_PRIVATE: u32 = 0x0002;
pub(super) const ACC_PROTECTED: u32 = 0x0004;
pub(super) const ACC_STATIC: u32 = 0x0008;
pub(super) const ACC_FINAL: u32 = 0x0010;
pub(super) const ACC_BRIDGE: u32 = 0x0040;
pub(super) const ACC_VOLATILE: u32 = 0x0040;
pub(super) const ACC_NATIVE: u32 = 0x0100;
pub(super) const ACC_SYNTHETIC: u32 = 0x1000;
pub(super) const ACC_CONSTRUCTOR: u32 = 0x0001_0000;
pub(super) const ACC_DECLARED_SYNCHRONIZED: u32 = 0x0002_0000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProtoSpec {
    pub return_type: String,
    pub params: Vec<String>,
}

impl ProtoSpec {
    pub(super) fn new(return_type: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            return_type: return_type.into(),
            params,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FieldRef {
    pub class_type: String,
    pub type_name: String,
    pub name: String,
}

impl FieldRef {
    pub(super) fn new(class_type: impl Into<String>, type_name: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            type_name: type_name.into(),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MethodRef {
    pub class_type: String,
    pub proto: ProtoSpec,
    pub name: String,
}

impl MethodRef {
    pub(super) fn new(
        class_type: impl Into<String>,
        name: impl Into<String>,
        return_type: impl Into<String>,
        params: Vec<String>,
    ) -> Self {
        Self {
            class_type: class_type.into(),
            proto: ProtoSpec::new(return_type, params),
            name: name.into(),
        }
    }
}

mod dex_ir;
use dex_ir::{value_kind_from_descriptor, DexIntBinOp, DexIntLit16Op, DexIntLit8Op, DexIrBuilder, IfCmpOp, ValueKind};

mod dex_writer;
use dex_writer::{DexBuilder, DexClass};

pub(super) struct GeneratedManagedDex {
    pub dex: Vec<u8>,
    pub class_name: String,
    pub method_name: String,
    pub method_sig: String,
    pub uses_orig: bool,
    pub string_literals: Vec<GeneratedStringLiteral>,
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedStringLiteral {
    pub field_name: String,
    pub value: String,
}

mod descriptor;
use descriptor::{
    array_component_descriptor, build_method_sig, build_params_sig, descriptor_list_word_count,
    descriptor_to_java_class_name, descriptor_word_count, java_class_to_descriptor,
    java_class_to_descriptor_or_primitive, parse_call_params, parse_method_params_signature, parse_method_signature,
    return_is_object,
};

fn emit_return_from_orig(ir: &mut DexIrBuilder, return_type: &str) -> Result<(), String> {
    match return_type {
        "V" => ir.return_void(),
        "J" | "D" => {
            ir.move_result_wide(0);
            ir.return_wide(0);
        }
        ret if return_is_object(ret) => {
            ir.move_result_object(0);
            ir.return_object(0);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.move_result(0);
            ir.return_value(0);
        }
        other => return Err(format!("unsupported return type '{}'", other)),
    }
    Ok(())
}

mod semantic;
use semantic::validate_semantics;

fn resolve_call_proto(
    env: JniEnv,
    stmt: &DslCallStmt,
    class_type: &str,
) -> Result<(Vec<String>, String, String), String> {
    if let Ok((params, return_type)) = parse_method_signature(&stmt.sig) {
        return Ok((params, return_type, stmt.sig.clone()));
    }

    let params = parse_method_params_signature(&stmt.sig)?;
    let params_sig = build_params_sig(&params);
    let class_name = descriptor_to_java_class_name(class_type)?;
    let is_static = matches!(stmt.kind, DslCallKind::Static);
    let collect_matches = |declared_only: bool, include_synthetic: bool| -> Result<BTreeSet<String>, String> {
        let methods = unsafe {
            if declared_only {
                enumerate_methods_declared_only(env, &class_name)
            } else {
                enumerate_methods(env, &class_name)
            }
        }?;
        let mut matches = BTreeSet::new();
        for method in methods {
            if method.name != stmt.method_name || method.is_static != is_static {
                continue;
            }
            if !include_synthetic && (method.modifiers & (ACC_BRIDGE as i32 | ACC_SYNTHETIC as i32)) != 0 {
                continue;
            }
            let Ok((method_params, _)) = parse_method_signature(&method.sig) else {
                continue;
            };
            if build_params_sig(&method_params) == params_sig {
                matches.insert(method.sig);
            }
        }
        Ok(matches)
    };

    let declared_matches = collect_matches(true, false)?;
    let matches = if declared_matches.is_empty() {
        let inherited_matches = collect_matches(false, false)?;
        if inherited_matches.is_empty() {
            collect_matches(false, true)?
        } else {
            inherited_matches
        }
    } else {
        declared_matches
    };

    match matches.len() {
        1 => {
            let full_sig = matches.into_iter().next().unwrap();
            let (params, return_type) = parse_method_signature(&full_sig)?;
            Ok((params, return_type, full_sig))
        }
        0 => Err(format!(
            "method not found for {}.{}{}; use a full JNI signature if reflection cannot resolve it",
            class_name, stmt.method_name, params_sig
        )),
        _ => Err(format!(
            "ambiguous method return for {}.{}{}; use overload(\"full JNI signature\")",
            class_name, stmt.method_name, params_sig
        )),
    }
}

mod emitter;
use emitter::{
    collect_local_slots, emit_statements, helper_param_layout, program_int_expr_scratch_count,
    program_max_invoke_words, program_uses_orig, validate_orig_bypass_flow, DslBuildContext, EmitContext,
    BASE_LOCAL_REG_COUNT,
};

pub(super) unsafe fn build_managed_dsl_dex(
    env: JniEnv,
    class_id: u64,
    target_class_name: &str,
    target_method_name: &str,
    target_sig: &str,
    is_static: bool,
    dsl: &str,
) -> Result<GeneratedManagedDex, String> {
    let program = parse_managed_dsl(dsl)?;
    let uses_orig = program_uses_orig(&program);
    if uses_orig {
        validate_orig_bypass_flow(&program)?;
    }
    let target_type = java_class_to_descriptor(target_class_name)?;
    let object_type = "Ljava/lang/Object;".to_string();
    let (target_params, return_type) = parse_method_signature(target_sig)?;
    let local_descriptors = validate_semantics(env, &program, is_static, target_type.clone(), target_params.clone())?;
    let mut helper_params = Vec::new();
    if !is_static {
        helper_params.push(target_type.clone());
    }
    helper_params.extend(target_params.clone());

    let ins_size = descriptor_list_word_count(&helper_params)?;
    if ins_size > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", ins_size));
    }
    let max_invoke_words = program_max_invoke_words(&program, &target_params, is_static)?;
    if max_invoke_words > u8::MAX as u16 {
        return Err(format!("too many DSL invoke argument words: {}", max_invoke_words));
    }
    let int_expr_scratch_count = program_int_expr_scratch_count(&program);
    let range_scratch_base = BASE_LOCAL_REG_COUNT
        .checked_add(int_expr_scratch_count)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let locals_start = range_scratch_base
        .checked_add(max_invoke_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let (local_slots, local_words) = collect_local_slots(&local_descriptors, locals_start)?;
    let local_count = locals_start
        .checked_add(local_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let registers_size = local_count
        .checked_add(ins_size)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let outs_size = std::cmp::max(1u16, std::cmp::max(ins_size, max_invoke_words));
    if registers_size > u8::MAX as u16 {
        return Err(format!(
            "too many dex registers for generated helper: {}",
            registers_size
        ));
    }

    let generated_type = format!("Lrustfrida/DynManagedHook{};", class_id);
    let generated_class_name = format!("rustfrida.DynManagedHook{}", class_id);
    let sink = FieldRef::new(generated_type.clone(), object_type.clone(), "sink");
    let mut dsl_ctx = DslBuildContext::new(
        env,
        generated_type.clone(),
        BASE_LOCAL_REG_COUNT,
        int_expr_scratch_count,
        range_scratch_base,
    );
    let target = MethodRef::new(
        target_type.clone(),
        target_method_name.to_string(),
        return_type.clone(),
        target_params.clone(),
    );
    let mut ir = DexIrBuilder::new(registers_size, ins_size, outs_size);
    let layout = helper_param_layout(is_static, &target_type, &target_params, local_count, local_slots)?;
    let mut emit_ctx = EmitContext {
        layout: &layout,
        dsl_ctx: &mut dsl_ctx,
        is_static,
        local_count,
        ins_size,
        target: &target,
        return_type: &return_type,
        sink: &sink,
    };
    let saw_return = emit_statements(&mut ir, &program.stmts, &mut emit_ctx)?;
    if !saw_return {
        return Err("managed DSL must end with return statement".to_string());
    }
    let code = ir.finish()?;

    let mut class = DexClass::new(generated_type.clone()).source_file("RustFridaDynamicManagedHook.java");
    class.static_field("sink", &object_type, ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
    for lit in &dsl_ctx.string_literals {
        class.static_field(
            &lit.field_name,
            "Ljava/lang/String;",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
    }
    class.direct_method(
        "hook",
        &return_type,
        helper_params.clone(),
        ACC_PUBLIC | ACC_STATIC,
        code,
    );

    let mut builder = DexBuilder::new();
    builder.add_class(class);
    builder.add_method_ref(target);
    let dex = builder.build()?;

    Ok(GeneratedManagedDex {
        dex,
        class_name: generated_class_name,
        method_name: "hook".to_string(),
        method_sig: build_method_sig(&helper_params, &return_type),
        uses_orig,
        string_literals: dsl_ctx.string_literals,
    })
}

mod dsl;
use dsl::{parse_managed_dsl, DslCallKind, DslCallStmt};
