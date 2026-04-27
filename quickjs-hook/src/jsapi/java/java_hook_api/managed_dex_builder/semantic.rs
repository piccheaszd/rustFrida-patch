use std::collections::{BTreeMap, BTreeSet};

use super::dsl::{
    DslCallKind, DslCallStmt, DslFieldStmt, DslOrigArgs, DslProgram, DslStmt, DslTarget, DslUnaryOp, DslValue,
};
use super::{
    array_component_descriptor, java_class_to_descriptor, java_class_to_descriptor_or_primitive,
    parse_method_signature, resolve_call_proto, return_is_object,
};
use crate::jsapi::java::jni_core::JniEnv;

struct DslSemanticContext {
    env: JniEnv,
    this_descriptor: Option<String>,
    arg_descriptors: Vec<String>,
    local_descriptors: BTreeMap<String, String>,
    nonnull_targets: BTreeSet<DslTargetKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DslTargetKey {
    This,
    Arg(usize),
    Local(String),
}

fn dsl_target_key(target: &DslTarget) -> Option<DslTargetKey> {
    match target {
        DslTarget::This => Some(DslTargetKey::This),
        DslTarget::Arg(index) => Some(DslTargetKey::Arg(*index)),
        DslTarget::Local(name) => Some(DslTargetKey::Local(name.clone())),
        DslTarget::Last | DslTarget::Result => None,
    }
}

fn dsl_target_label(target: &DslTarget) -> String {
    match target {
        DslTarget::This => "this".to_string(),
        DslTarget::Arg(index) => format!("arg{}", index),
        DslTarget::Local(name) => name.clone(),
        DslTarget::Last => "last".to_string(),
        DslTarget::Result => "result".to_string(),
    }
}

fn value_descriptor_assignable_to(src: &str, dst: &str) -> bool {
    src == dst || (return_is_object(src) && return_is_object(dst))
}

impl DslSemanticContext {
    fn new(env: JniEnv, is_static: bool, target_type: String, target_params: Vec<String>) -> Self {
        Self {
            env,
            this_descriptor: if is_static { None } else { Some(target_type) },
            arg_descriptors: target_params,
            local_descriptors: BTreeMap::new(),
            nonnull_targets: BTreeSet::new(),
        }
    }

    fn resolve_target_descriptor(&self, target: &DslTarget) -> Result<String, String> {
        match target {
            DslTarget::This => self
                .this_descriptor
                .clone()
                .ok_or_else(|| "static target has no this descriptor".to_string()),
            DslTarget::Arg(index) => self
                .arg_descriptors
                .get(*index)
                .cloned()
                .ok_or_else(|| format!("argument {} does not exist", index)),
            DslTarget::Local(name) => self
                .local_descriptors
                .get(name)
                .cloned()
                .ok_or_else(|| format!("local '{}' is not declared", name)),
            DslTarget::Last | DslTarget::Result => {
                Err("target class cannot be inferred for last/result; pass the class name explicitly".to_string())
            }
        }
    }

    fn resolve_member_class_type(
        &self,
        explicit_class_name: Option<&str>,
        target: Option<&DslTarget>,
        receiver: Option<&DslValue>,
    ) -> Result<String, String> {
        if let Some(class_name) = explicit_class_name {
            return java_class_to_descriptor(class_name);
        }
        if let Some(receiver) = receiver {
            let Some(desc) = self.infer_value_descriptor(receiver)? else {
                return Err("receiver class cannot be inferred from null/void expression".to_string());
            };
            if !desc.starts_with('L') || !desc.ends_with(';') {
                return Err(format!(
                    "receiver class can only be inferred from object expressions, got {}",
                    desc
                ));
            }
            return Ok(desc);
        }
        let Some(target) = target else {
            return Err("static member access requires an explicit class name".to_string());
        };
        let desc = self.resolve_target_descriptor(target)?;
        if !desc.starts_with('L') || !desc.ends_with(';') {
            return Err(format!(
                "target class can only be inferred from object locals/args, got {}",
                desc
            ));
        }
        Ok(desc)
    }

    fn infer_value_descriptor(&self, value: &DslValue) -> Result<Option<String>, String> {
        match value {
            DslValue::Target(target) => self.resolve_target_descriptor(target).map(Some),
            DslValue::String(_) => Ok(Some("Ljava/lang/String;".to_string())),
            DslValue::Int(_) | DslValue::IntBinOp { .. } | DslValue::ArrayLength(_) => Ok(Some("I".to_string())),
            DslValue::UnaryOp { op, .. } => match op {
                DslUnaryOp::Neg | DslUnaryOp::BitNot => Ok(Some("I".to_string())),
                DslUnaryOp::BoolNot => Ok(Some("Z".to_string())),
            },
            DslValue::Bool(_) => Ok(Some("Z".to_string())),
            DslValue::Null => Ok(None),
            DslValue::Call(stmt) => {
                let class_type = self.resolve_member_class_type(
                    stmt.class_name.as_deref(),
                    stmt.target.as_ref(),
                    stmt.receiver.as_deref(),
                )?;
                let (_, return_type, _) = resolve_call_proto(self.env, stmt, &class_type)?;
                if return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(return_type))
                }
            }
            DslValue::NewObject { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
            DslValue::FieldGet { stmt, .. } => java_class_to_descriptor_or_primitive(&stmt.type_name).map(Some),
            DslValue::Cast { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
            DslValue::ArrayGet { type_name, array, .. } => match type_name {
                Some(type_name) => java_class_to_descriptor_or_primitive(type_name).map(Some),
                None => {
                    let Some(array_desc) = self.infer_value_descriptor(array)? else {
                        return Ok(None);
                    };
                    array_component_descriptor(&array_desc).map(Some)
                }
            },
        }
    }

    fn is_known_nonnull_target(&self, target: &DslTarget) -> bool {
        matches!(target, DslTarget::This)
            || dsl_target_key(target)
                .map(|key| self.nonnull_targets.contains(&key))
                .unwrap_or(false)
    }

    fn validate_receiver_nonnull(&self, stmt: &DslCallStmt, class_type: &str) -> Result<(), String> {
        if stmt.kind == DslCallKind::Static || !return_is_object(class_type) {
            return Ok(());
        }
        if stmt.receiver.is_some() {
            return Ok(());
        }
        let Some(target) = stmt.target.as_ref() else {
            return Ok(());
        };
        if self.is_known_nonnull_target(target) {
            return Ok(());
        }
        Err(format!(
            "receiver '{}' may be null before calling {}.{}; guard it with '{} != null' first",
            dsl_target_label(target),
            stmt.class_label(),
            stmt.method_name,
            dsl_target_label(target)
        ))
    }

    fn validate_value(&mut self, value: &DslValue) -> Result<(), String> {
        self.validate_value_inner(value, false)
    }

    fn validate_bool_condition_value(&mut self, value: &DslValue) -> Result<(), String> {
        self.validate_value_inner(value, true)
    }

    fn validate_value_inner(&mut self, value: &DslValue, require_nonnull_receiver: bool) -> Result<(), String> {
        match value {
            DslValue::Target(target) => {
                self.resolve_target_descriptor(target)?;
            }
            DslValue::String(_) | DslValue::Int(_) | DslValue::Bool(_) | DslValue::Null => {}
            DslValue::UnaryOp { op, value } => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
                let Some(desc) = self.infer_value_descriptor(value)? else {
                    return Err("unary expression type cannot be inferred".to_string());
                };
                match op {
                    DslUnaryOp::Neg | DslUnaryOp::BitNot if desc != "I" => {
                        return Err(format!("int unary expression requires int, got {}", desc));
                    }
                    DslUnaryOp::BoolNot if desc != "Z" => {
                        return Err(format!("boolean unary expression requires boolean, got {}", desc));
                    }
                    _ => {}
                }
            }
            DslValue::ArrayLength(value) => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
            }
            DslValue::IntBinOp { left, right, .. } => {
                self.validate_value_inner(left, require_nonnull_receiver)?;
                self.validate_value_inner(right, require_nonnull_receiver)?;
            }
            DslValue::Cast { value, class_name } => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
                java_class_to_descriptor(class_name)?;
            }
            DslValue::ArrayGet { array, index, .. } => {
                self.validate_value_inner(array, require_nonnull_receiver)?;
                self.validate_value_inner(index, require_nonnull_receiver)?;
                if self.infer_value_descriptor(array)?.is_none() {
                    return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
                }
            }
            DslValue::NewObject {
                class_name,
                ctor_sig,
                args,
            } => {
                java_class_to_descriptor(class_name)?;
                let params = if let Some(sig) = ctor_sig {
                    let (params, return_type) = parse_method_signature(sig)?;
                    if return_type != "V" {
                        return Err(format!("constructor signature must return void, got '{}'", return_type));
                    }
                    params
                } else {
                    if args.is_empty() {
                        Vec::new()
                    } else {
                        return Err(
                            "constructor arguments must include a full JNI signature or parameter type list"
                                .to_string(),
                        );
                    }
                };
                if params.len() != args.len() {
                    return Err(format!(
                        "constructor expects {} explicit args, got {}",
                        params.len(),
                        args.len()
                    ));
                }
                for arg in args {
                    self.validate_value_inner(arg, require_nonnull_receiver)?;
                }
            }
            DslValue::Call(stmt) => {
                if let Some(receiver) = &stmt.receiver {
                    self.validate_value_inner(receiver, require_nonnull_receiver)?;
                }
                self.validate_call_inner(stmt, require_nonnull_receiver)?;
            }
            DslValue::FieldGet { stmt, .. } => {
                if let Some(receiver) = &stmt.receiver {
                    self.validate_value_inner(receiver, require_nonnull_receiver)?;
                }
                self.validate_field(stmt)?;
            }
        }
        Ok(())
    }

    fn validate_call(&mut self, stmt: &DslCallStmt) -> Result<(), String> {
        self.validate_call_inner(stmt, false)
    }

    fn validate_call_inner(&mut self, stmt: &DslCallStmt, require_nonnull_receiver: bool) -> Result<(), String> {
        if stmt.target.is_some() && stmt.receiver.is_some() {
            return Err("method call cannot use both target and receiver expression".to_string());
        }
        if stmt.kind == DslCallKind::Static && stmt.receiver.is_some() {
            return Err("static method call cannot use a receiver expression".to_string());
        }
        let class_type = self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        let (params, _, full_sig) = resolve_call_proto(self.env, stmt, &class_type)?;
        if require_nonnull_receiver {
            self.validate_receiver_nonnull(stmt, &class_type)?;
        }
        if let Some(receiver) = &stmt.receiver {
            self.validate_value_inner(receiver, require_nonnull_receiver)?;
        }
        if params.len() != stmt.args.len() {
            return Err(format!(
                "{}.{}{} expects {} explicit args, got {}",
                stmt.class_label(),
                stmt.method_name,
                full_sig,
                params.len(),
                stmt.args.len()
            ));
        }
        for arg in &stmt.args {
            self.validate_value_inner(arg, require_nonnull_receiver)?;
        }
        Ok(())
    }

    fn validate_field(&mut self, stmt: &DslFieldStmt) -> Result<(), String> {
        if stmt.target.is_some() && stmt.receiver.is_some() {
            return Err("field access cannot use both target and receiver expression".to_string());
        }
        self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        if let Some(receiver) = &stmt.receiver {
            self.validate_value(receiver)?;
        }
        java_class_to_descriptor_or_primitive(&stmt.type_name)?;
        if let Some(value) = &stmt.value {
            self.validate_value(value)?;
        }
        Ok(())
    }

    fn validate_orig_args(&mut self, args: &DslOrigArgs) -> Result<(), String> {
        let DslOrigArgs::Values(values) = args else {
            return Ok(());
        };
        if values.len() != self.arg_descriptors.len() {
            return Err(format!(
                "orig(...) expects {} argument(s), got {}",
                self.arg_descriptors.len(),
                values.len()
            ));
        }
        for value in values {
            self.validate_value(value)?;
        }
        Ok(())
    }

    fn validate_stmts(&mut self, stmts: &[DslStmt]) -> Result<(), String> {
        for stmt in stmts {
            self.validate_stmt(stmt)?;
        }
        Ok(())
    }

    fn validate_stmts_with_nonnull_value(&mut self, value: &DslValue, stmts: &[DslStmt]) -> Result<(), String> {
        let DslValue::Target(target) = value else {
            return self.validate_stmts(stmts);
        };
        let Some(key) = dsl_target_key(target) else {
            return self.validate_stmts(stmts);
        };
        let inserted = self.nonnull_targets.insert(key.clone());
        let result = self.validate_stmts(stmts);
        if inserted {
            self.nonnull_targets.remove(&key);
        }
        result
    }

    fn validate_stmt(&mut self, stmt: &DslStmt) -> Result<(), String> {
        match stmt {
            DslStmt::Block(stmts) => self.validate_stmts(stmts)?,
            DslStmt::Let { name, type_name, value } => {
                self.validate_value(value)?;
                let descriptor = if let Some(type_name) = type_name {
                    let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
                    if let Some(value_desc) = self.infer_value_descriptor(value)? {
                        if !value_descriptor_assignable_to(&value_desc, &descriptor) {
                            return Err(format!(
                                "local '{}' type mismatch: cannot assign {} to {}",
                                name, value_desc, descriptor
                            ));
                        }
                    } else if !return_is_object(&descriptor) {
                        return Err(format!(
                            "local '{}' type mismatch: cannot assign null/void to {}",
                            name, descriptor
                        ));
                    }
                    descriptor
                } else {
                    self.infer_value_descriptor(value)?
                        .ok_or_else(|| format!("local '{}' type cannot be inferred", name))?
                };
                self.local_descriptors.entry(name.clone()).or_insert(descriptor);
            }
            DslStmt::Assign { name, value } => {
                let Some(descriptor) = self.local_descriptors.get(name).cloned() else {
                    return Err(format!("local '{}' is not declared", name));
                };
                self.validate_value(value)?;
                if let Some(value_desc) = self.infer_value_descriptor(value)? {
                    if !value_descriptor_assignable_to(&value_desc, &descriptor) {
                        return Err(format!(
                            "local '{}' type mismatch: cannot assign {} to {}",
                            name, value_desc, descriptor
                        ));
                    }
                } else if !return_is_object(&descriptor) {
                    return Err(format!(
                        "local '{}' type mismatch: cannot assign null/void to {}",
                        name, descriptor
                    ));
                }
            }
            DslStmt::LetOrig { name, type_name, args } => {
                let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
                self.validate_orig_args(args)?;
                self.local_descriptors.entry(name.clone()).or_insert(descriptor);
            }
            DslStmt::New {
                class_name,
                ctor_sig,
                args,
            } => self.validate_value(&DslValue::NewObject {
                class_name: class_name.clone(),
                ctor_sig: ctor_sig.clone(),
                args: args.clone(),
            })?,
            DslStmt::NewArray { array_type_name, size } => {
                let desc = java_class_to_descriptor_or_primitive(array_type_name)?;
                if !desc.starts_with('[') {
                    return Err(format!("new array requires an array type, got '{}'", array_type_name));
                }
                self.validate_value(size)?;
            }
            DslStmt::Call(stmt) => self.validate_call(stmt)?,
            DslStmt::Cast { value, class_name } => {
                self.validate_value(value)?;
                java_class_to_descriptor(class_name)?;
            }
            DslStmt::ArrayLength { array } => self.validate_value(array)?,
            DslStmt::ArrayGet {
                array,
                index,
                type_name,
            } => {
                self.validate_value(array)?;
                self.validate_value(index)?;
                if let Some(type_name) = type_name {
                    java_class_to_descriptor_or_primitive(type_name)?;
                } else if self.infer_value_descriptor(array)?.is_none() {
                    return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
                }
            }
            DslStmt::ArrayPut {
                array,
                index,
                type_name,
                value,
            } => {
                self.validate_value(array)?;
                self.validate_value(index)?;
                self.validate_value(value)?;
                if let Some(type_name) = type_name {
                    java_class_to_descriptor_or_primitive(type_name)?;
                }
            }
            DslStmt::FieldRead { stmt, .. } | DslStmt::FieldWrite { stmt, .. } => self.validate_field(stmt)?,
            DslStmt::IfNull {
                value,
                invert,
                then_stmts,
                else_stmts,
            } => {
                self.validate_value(value)?;
                if *invert {
                    self.validate_stmts_with_nonnull_value(value, then_stmts)?;
                    self.validate_stmts(else_stmts)?;
                } else {
                    self.validate_stmts(then_stmts)?;
                    self.validate_stmts_with_nonnull_value(value, else_stmts)?;
                }
            }
            DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            } => {
                self.validate_bool_condition_value(value)?;
                self.validate_stmts(then_stmts)?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::IfInstanceOf {
                value,
                then_stmts,
                else_stmts,
                ..
            } => {
                self.validate_value(value)?;
                self.validate_stmts_with_nonnull_value(value, then_stmts)?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::IfCmp {
                left,
                right,
                then_stmts,
                else_stmts,
                ..
            } => {
                self.validate_value(left)?;
                self.validate_value(right)?;
                self.validate_stmts(then_stmts)?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::Switch {
                value,
                cases,
                default_stmts,
            } => {
                self.validate_value(value)?;
                for (_, stmts) in cases {
                    self.validate_stmts(stmts)?;
                }
                if let Some(stmts) = default_stmts {
                    self.validate_stmts(stmts)?;
                }
            }
            DslStmt::ReturnOrig { args } => self.validate_orig_args(args)?,
            DslStmt::ReturnValue { value } => {
                if let Some(value) = value {
                    self.validate_value(value)?;
                }
            }
        }
        Ok(())
    }
}

pub(super) fn validate_semantics(
    env: JniEnv,
    program: &DslProgram,
    is_static: bool,
    target_type: String,
    target_params: Vec<String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut ctx = DslSemanticContext::new(env, is_static, target_type, target_params);
    ctx.validate_stmts(&program.stmts)?;
    Ok(ctx.local_descriptors)
}
