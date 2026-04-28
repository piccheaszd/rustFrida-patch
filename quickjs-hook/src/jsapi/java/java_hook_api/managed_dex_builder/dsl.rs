use super::{build_method_sig, build_params_sig, java_class_to_descriptor_or_primitive, IfCmpOp};

mod assignment;
mod ast;
mod condition;
mod control_flow;
mod control_loop;
mod control_switch;
mod control_try;
pub(super) use ast::*;
mod cursor;
mod declaration;
mod lexer;
mod member;
mod member_args;
mod member_call;
mod member_new;
mod member_overload;
use lexer::TokenKind as DslTokenKind;
mod operators;
mod parser;
use parser::{DslMark, DslParser};
mod scope;
mod statement_tail;
mod syntax;

mod expr_core;
mod expression;
mod helpers;
pub(super) use helpers::*;
mod statement;

pub(super) fn parse_managed_dsl(dsl: &str) -> Result<DslProgram, String> {
    let mut parser = DslParser::new(dsl)?;
    let stmts = parser.parse_statements(false)?;
    parser.skip_ws();
    parser.expect_eof()?;
    Ok(DslProgram { stmts })
}
