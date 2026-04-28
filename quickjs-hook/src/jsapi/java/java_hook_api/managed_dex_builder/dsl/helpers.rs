use super::*;

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn parse_target_name(name: &str) -> Option<DslTarget> {
    match name {
        "this" | "$this" => Some(DslTarget::This),
        "last" | "$last" => Some(DslTarget::Last),
        "result" | "$result" => Some(DslTarget::Result),
        value if value.starts_with("arg") => value[3..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('$') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('p') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if is_local_ident(value) => Some(DslTarget::Local(value.to_string())),
        _ => None,
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn looks_like_type_name(value: &str) -> bool {
    matches!(
        value,
        "boolean" | "byte" | "char" | "short" | "int" | "long" | "float" | "double" | "void"
    ) || matches!(value, "Z" | "B" | "C" | "S" | "I" | "J" | "F" | "D" | "V")
        || value.starts_with('[')
        || (value.starts_with('L') && value.ends_with(';'))
        || value.ends_with("[]")
        || value.contains('.')
        || value.contains('/')
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn looks_like_static_class_name(value: &str) -> bool {
    value.chars().next().map(|ch| ch.is_ascii_uppercase()).unwrap_or(false)
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn fold_unary_op(
    op: DslUnaryOp,
    value: DslValue,
) -> DslValue {
    match (op, value) {
        (DslUnaryOp::Neg, DslValue::Int(value)) => {
            value
                .checked_neg()
                .map(DslValue::Int)
                .unwrap_or_else(|| DslValue::UnaryOp {
                    op,
                    value: Box::new(DslValue::Int(value)),
                })
        }
        (DslUnaryOp::BitNot, DslValue::Int(value)) => DslValue::Int(!value),
        (DslUnaryOp::BoolNot, DslValue::Bool(value)) => DslValue::Bool(!value),
        (op, value) => DslValue::UnaryOp {
            op,
            value: Box::new(value),
        },
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn fold_int_binop(
    op: DslIntBinOp,
    left: DslValue,
    right: DslValue,
) -> DslValue {
    let (DslValue::Int(left_value), DslValue::Int(right_value)) = (&left, &right) else {
        return simplify_int_binop(op, left, right);
    };
    let Some(folded) = eval_const_int_binop(op, *left_value as i32, *right_value as i32) else {
        return simplify_int_binop(op, left, right);
    };
    if folded < i16::MIN as i32 || folded > i16::MAX as i32 {
        return simplify_int_binop(op, left, right);
    }
    DslValue::Int(folded as i16)
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn simplify_int_binop(
    op: DslIntBinOp,
    left: DslValue,
    right: DslValue,
) -> DslValue {
    let left_int = value_int_literal(&left);
    let right_int = value_int_literal(&right);
    match op {
        DslIntBinOp::Add => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return right;
            }
        }
        DslIntBinOp::Sub => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return fold_unary_op(DslUnaryOp::Neg, right);
            }
        }
        DslIntBinOp::Mul => {
            if right_int == Some(1) {
                return left;
            }
            if left_int == Some(1) {
                return right;
            }
        }
        DslIntBinOp::Div => {
            if right_int == Some(1) {
                return left;
            }
        }
        DslIntBinOp::And => {
            if right_int == Some(-1) {
                return left;
            }
            if left_int == Some(-1) {
                return right;
            }
        }
        DslIntBinOp::Or | DslIntBinOp::Xor => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return right;
            }
        }
        DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => {
            if right_int == Some(0) {
                return left;
            }
        }
        DslIntBinOp::Rem => {}
    }
    DslValue::IntBinOp {
        op,
        left: Box::new(left),
        right: Box::new(right),
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn value_int_literal(value: &DslValue) -> Option<i16> {
    let DslValue::Int(value) = value else {
        return None;
    };
    Some(*value)
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn eval_const_int_binop(
    op: DslIntBinOp,
    left: i32,
    right: i32,
) -> Option<i32> {
    let value = match op {
        DslIntBinOp::Add => left.wrapping_add(right),
        DslIntBinOp::Sub => left.wrapping_sub(right),
        DslIntBinOp::Mul => left.wrapping_mul(right),
        DslIntBinOp::Div => {
            if right == 0 {
                return None;
            }
            left.wrapping_div(right)
        }
        DslIntBinOp::Rem => {
            if right == 0 {
                return None;
            }
            left.wrapping_rem(right)
        }
        DslIntBinOp::And => left & right,
        DslIntBinOp::Or => left | right,
        DslIntBinOp::Xor => left ^ right,
        DslIntBinOp::Shl => left.wrapping_shl((right & 0x1f) as u32),
        DslIntBinOp::Shr => left.wrapping_shr((right & 0x1f) as u32),
        DslIntBinOp::Ushr => ((left as u32).wrapping_shr((right & 0x1f) as u32)) as i32,
    };
    Some(value)
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn is_local_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == '$' {
        return false;
    }
    first == '_' || first.is_ascii_alphabetic()
}
