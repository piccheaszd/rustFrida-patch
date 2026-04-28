use super::IfCmpOp;

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslProgram {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) stmts: Vec<DslStmt>,
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslStmt {
    Block(Vec<DslStmt>),
    Let {
        name: String,
        type_name: Option<String>,
        value: DslValue,
    },
    Assign {
        name: String,
        value: DslValue,
    },
    LetOrig {
        name: String,
        type_name: Option<String>,
        args: DslOrigArgs,
    },
    New {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    NewArray {
        array_type_name: String,
        size: DslValue,
    },
    Call(DslCallStmt),
    Cast {
        value: DslValue,
        class_name: String,
    },
    ArrayLength {
        array: DslValue,
    },
    ArrayGet {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
    },
    ArrayPut {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
        value: DslValue,
    },
    ArrayUpdate {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
        op: DslIntBinOp,
        value: DslValue,
    },
    FieldRead {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    FieldWrite {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    FieldUpdate {
        stmt: DslFieldStmt,
        is_static: bool,
        op: DslIntBinOp,
        value: DslValue,
    },
    IfNull {
        value: DslValue,
        invert: bool,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfBool {
        value: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfCmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfInstanceOf {
        value: DslValue,
        class_name: String,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    Switch {
        value: DslValue,
        cases: Vec<(i16, Vec<DslStmt>)>,
        default_stmts: Option<Vec<DslStmt>>,
    },
    TryCatch {
        try_stmts: Vec<DslStmt>,
        catches: Vec<DslCatch>,
    },
    While {
        condition: DslCondition,
        body_stmts: Vec<DslStmt>,
    },
    DoWhile {
        body_stmts: Vec<DslStmt>,
        condition: DslCondition,
    },
    For {
        init_stmts: Vec<DslStmt>,
        condition: Option<DslCondition>,
        update_stmts: Vec<DslStmt>,
        body_stmts: Vec<DslStmt>,
    },
    Break,
    Continue,
    Count {
        name: String,
    },
    Throw {
        value: DslValue,
    },
    ReturnOrig {
        args: DslOrigArgs,
    },
    ReturnValue {
        value: Option<DslValue>,
    },
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslCatch {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) catch_type: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) catch_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) catch_stmts: Vec<DslStmt>,
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslOrigArgs {
    Original,
    Values(Vec<DslValue>),
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslCallStmt {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) kind: DslCallKind,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) target: Option<DslTarget>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) receiver: Option<Box<DslValue>>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) null_safe: bool,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) class_name: Option<String>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) method_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) sig: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) args: Vec<DslValue>,
}

impl DslCallStmt {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn class_label(&self) -> &str {
        self.class_name.as_deref().unwrap_or("<inferred>")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslCallKind {
    Virtual,
    Interface,
    Static,
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum ParsedCallArgs {
    Direct(Vec<DslValue>),
    LegacyCall {
        class_name: Option<String>,
        sig: String,
        args: Vec<DslValue>,
    },
    Field {
        class_name: Option<String>,
        type_name: String,
    },
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslFieldStmt {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) target: Option<DslTarget>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) receiver: Option<Box<DslValue>>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) class_name: Option<String>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) field_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) type_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) value: Option<DslValue>,
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslValue {
    Target(DslTarget),
    String(String),
    Int(i16),
    Bool(bool),
    Null,
    UnaryOp {
        op: DslUnaryOp,
        value: Box<DslValue>,
    },
    IntBinOp {
        op: DslIntBinOp,
        left: Box<DslValue>,
        right: Box<DslValue>,
    },
    Ternary {
        condition: Box<DslCondition>,
        then_value: Box<DslValue>,
        else_value: Box<DslValue>,
    },
    OrigCall(DslOrigArgs),
    Call(DslCallStmt),
    NewObject {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    FieldGet {
        stmt: Box<DslFieldStmt>,
        is_static: bool,
    },
    Cast {
        value: Box<DslValue>,
        class_name: String,
    },
    ArrayLength(Box<DslValue>),
    ArrayLiteral {
        elements: Vec<DslValue>,
    },
    ArrayGet {
        array: Box<DslValue>,
        index: Box<DslValue>,
        type_name: Option<String>,
    },
}

#[derive(Clone, Copy)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslUnaryOp {
    Neg,
    BitNot,
    BoolNot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslIntBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslCondition {
    Null {
        value: DslValue,
        invert: bool,
    },
    Cmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
    },
    InstanceOf {
        value: DslValue,
        class_name: String,
    },
    Bool {
        value: DslValue,
    },
    Const(bool),
    And(Box<DslCondition>, Box<DslCondition>),
    Or(Box<DslCondition>, Box<DslCondition>),
    Not(Box<DslCondition>),
}

impl DslCondition {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn into_if_stmt(
        self,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    ) -> DslStmt {
        match self {
            DslCondition::Const(true) => DslStmt::Block(then_stmts),
            DslCondition::Const(false) => DslStmt::Block(else_stmts),
            DslCondition::Null { value, invert } => DslStmt::IfNull {
                value,
                invert,
                then_stmts,
                else_stmts,
            },
            DslCondition::Bool { value } => DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            },
            DslCondition::Cmp { op, left, right } => DslStmt::IfCmp {
                op,
                left,
                right,
                then_stmts,
                else_stmts,
            },
            DslCondition::InstanceOf { value, class_name } => DslStmt::IfInstanceOf {
                value,
                class_name,
                then_stmts,
                else_stmts,
            },
            DslCondition::And(left, right) => {
                let inner = right.into_if_stmt(then_stmts, else_stmts.clone());
                left.into_if_stmt(vec![inner], else_stmts)
            }
            DslCondition::Or(left, right) => {
                let inner = right.into_if_stmt(then_stmts.clone(), else_stmts);
                left.into_if_stmt(then_stmts, vec![inner])
            }
            DslCondition::Not(condition) => condition.into_if_stmt(else_stmts, then_stmts),
        }
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn condition_and(
    left: DslCondition,
    right: DslCondition,
) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(false), _) | (_, DslCondition::Const(false)) => DslCondition::Const(false),
        (DslCondition::Const(true), right) => right,
        (left, DslCondition::Const(true)) => left,
        (left, right) => DslCondition::And(Box::new(left), Box::new(right)),
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn condition_or(
    left: DslCondition,
    right: DslCondition,
) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(true), _) | (_, DslCondition::Const(true)) => DslCondition::Const(true),
        (DslCondition::Const(false), right) => right,
        (left, DslCondition::Const(false)) => left,
        (left, right) => DslCondition::Or(Box::new(left), Box::new(right)),
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn condition_not(
    condition: DslCondition,
) -> DslCondition {
    match condition {
        DslCondition::Const(value) => DslCondition::Const(!value),
        DslCondition::Not(inner) => *inner,
        other => DslCondition::Not(Box::new(other)),
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn fold_ternary(
    condition: DslCondition,
    then_value: DslValue,
    else_value: DslValue,
) -> DslValue {
    match condition {
        DslCondition::Const(true) => then_value,
        DslCondition::Const(false) => else_value,
        condition => DslValue::Ternary {
            condition: Box::new(condition),
            then_value: Box::new(then_value),
            else_value: Box::new(else_value),
        },
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn single_or_block(mut stmts: Vec<DslStmt>) -> DslStmt {
    if stmts.len() == 1 {
        stmts.remove(0)
    } else {
        DslStmt::Block(stmts)
    }
}

impl DslValue {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn into_bool_condition(self) -> DslCondition {
        match self {
            DslValue::Bool(value) => DslCondition::Const(value),
            value => DslCondition::Bool { value },
        }
    }

    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn into_statement(self) -> Option<DslStmt> {
        match self {
            DslValue::Call(stmt) => Some(DslStmt::Call(stmt)),
            DslValue::NewObject {
                class_name,
                ctor_sig,
                args,
            } => Some(DslStmt::New {
                class_name,
                ctor_sig,
                args,
            }),
            DslValue::FieldGet { stmt, is_static } => Some(DslStmt::FieldRead { stmt: *stmt, is_static }),
            DslValue::Cast { value, class_name } => Some(DslStmt::Cast {
                value: *value,
                class_name,
            }),
            DslValue::ArrayLength(array) => Some(DslStmt::ArrayLength { array: *array }),
            DslValue::ArrayGet {
                array,
                index,
                type_name,
            } => Some(DslStmt::ArrayGet {
                array: *array,
                index: *index,
                type_name,
            }),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslTarget {
    This,
    Arg(usize),
    Last,
    Result,
    Local(String),
}
