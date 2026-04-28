use super::{build_params_sig, java_class_to_descriptor_or_primitive, IfCmpOp};

mod assignment;
mod ast;
mod ast_call;
mod ast_condition;
mod ast_expr;
pub(super) use ast_condition::*;
mod ast_stmt;
pub(super) use ast_stmt::*;
mod ast_value;
mod condition;
mod control_flow;
mod control_loop;
mod control_switch;
mod control_try;
pub(super) use ast::*;
pub(super) use ast_call::*;
pub(super) use ast_expr::*;
mod cursor;
mod declaration;
mod expr_v2;
mod lexer;
use lexer::TokenKind as DslTokenKind;
mod operators;
mod parser;
use parser::{DslMark, DslParser};
mod scope;
mod statement_tail;
mod syntax;
mod token_stream;

mod expr_core;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expression_v2_parses_direct_receiver_call_as_primary_path() {
        let program = parse_managed_dsl("return this.size();").unwrap();
        let [DslStmt::ReturnValue {
            value: Some(DslValue::Call(call)),
        }] = program.stmts.as_slice()
        else {
            panic!("expected return call");
        };
        assert_eq!(call.method_name, "size");
        assert_eq!(call.sig, "");
        assert!(matches!(call.target.as_ref(), Some(DslTarget::This)));
        assert!(call.receiver.is_none());
        assert!(call.args.is_empty());
    }

    #[test]
    fn expression_v2_parses_expression_statement_receiver_call() {
        let program = parse_managed_dsl("this.clear();").unwrap();
        let [DslStmt::Call(call)] = program.stmts.as_slice() else {
            panic!("expected call statement");
        };
        assert_eq!(call.method_name, "clear");
        assert_eq!(call.sig, "");
        assert!(matches!(call.target.as_ref(), Some(DslTarget::This)));
        assert!(call.receiver.is_none());
        assert!(call.args.is_empty());
    }

    #[test]
    fn expression_v2_parses_for_update_receiver_call() {
        let program = parse_managed_dsl("for (; true; this.clear()) { break; }").unwrap();
        let [DslStmt::For { update_stmts, .. }] = program.stmts.as_slice() else {
            panic!("expected for statement");
        };
        let [DslStmt::Call(call)] = update_stmts.as_slice() else {
            panic!("expected call update");
        };
        assert_eq!(call.method_name, "clear");
        assert!(matches!(call.target.as_ref(), Some(DslTarget::This)));
    }

    #[test]
    fn expression_v2_parses_chained_member_call_without_fallback() {
        let program = parse_managed_dsl("return this.entrySet().iterator().hasNext();").unwrap();
        let [DslStmt::ReturnValue {
            value: Some(DslValue::Call(call)),
        }] = program.stmts.as_slice()
        else {
            panic!("expected return call");
        };
        assert_eq!(call.method_name, "hasNext");
        assert!(call.receiver.is_some());
    }

    #[test]
    fn expression_v2_parses_parenthesized_ternary_condition() {
        let program = parse_managed_dsl(
            "let has: boolean = this.containsKey(arg0); if (((this.size() >= 0 && has) ? true : false)) { return orig(arg0, arg1); } return orig(arg0, arg1);",
        )
        .unwrap();
        assert_eq!(program.stmts.len(), 3);
    }

    #[test]
    fn expression_v2_parses_bitwise_group_before_comparison() {
        let program = parse_managed_dsl(
            "let n: int = this.size(); if ((n & 1023) == 0) { send(\"size\", n); } return orig(arg0, arg1);",
        )
        .unwrap();
        assert_eq!(program.stmts.len(), 3);
    }

    #[test]
    fn expression_v2_parses_condition_ternary_with_comparison_branch() {
        let program = parse_managed_dsl(
            "let n: int = this.size();\
             let has: boolean = this.containsKey(arg0);\
             let keys: java.util.Set = this.keySet();\
             let it: java.util.Iterator = keys.iterator();\
             if (((has && it.hasNext()) ? true : n >= 0)) { count(\"hit\"); }\
             return orig(arg0, arg1);",
        )
        .unwrap();
        assert_eq!(program.stmts.len(), 6);
    }

    #[test]
    fn expression_v2_parses_parenthesized_value_ternary() {
        let program = parse_managed_dsl(
            "let selected: java.lang.Object = (arg0 != null ? arg0 : arg1); return selected;",
        )
        .unwrap();
        assert_eq!(program.stmts.len(), 2);
    }

    #[test]
    fn expression_v2_parses_comprehensive_expression_and_type_surface() {
        let program = parse_managed_dsl(
            "count(\"hit\");\
             let n: int = this.size();\
             let calc: int = (((n + 3) * 2) - 1) ^ ((n << 1) | (n >>> 1));\
             calc += (~n & 7);\
             let neg: int = -calc;\
             let maxv: int = java.lang.Integer.MAX_VALUE(\"int\");\
             let ok: boolean = this.containsKey(arg0);\
             let keys: java.util.Set = this.keySet();\
             let it: java.util.Iterator = keys.iterator();\
             let selected: java.lang.Object = ok ? arg0 : arg1;\
             let sb: java.lang.StringBuilder = new java.lang.StringBuilder(\"rf\");\
             sb.append(selected);\
             let text: java.lang.String = java.lang.String.valueOf(selected);\
             let asObj: java.lang.Object = text as java.lang.Object;\
             let objs: java.lang.Object[] = [selected, asObj, null];\
             let obj0: java.lang.Object = objs[0];\
             let arr: int[] = new int[n + 3];\
             arr[0] = calc;\
             arr[0] += n;\
             arr[0]++;\
             for (let i: int = 0; i < 2; i++) { arr[0] += i; }\
             if ((((ok && it.hasNext()) ? true : false) || arr.length > 0)) { java.lang.String.valueOf(obj0); }\
             return orig(arg0, arg1);",
        )
        .unwrap();

        assert!(matches!(program.stmts.first(), Some(DslStmt::Count { name }) if name == "hit"));
        assert!(program.stmts.iter().any(|stmt| matches!(
            stmt,
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::FieldGet { is_static: true, .. },
                ..
            } if type_name == "int"
        )));
        assert!(program.stmts.iter().any(|stmt| matches!(
            stmt,
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::ArrayLiteral { .. },
                ..
            } if type_name == "java.lang.Object[]"
        )));
        assert!(program.stmts.iter().any(|stmt| matches!(
            stmt,
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::NewArray { .. },
                ..
            } if type_name == "int[]"
        )));
        assert!(program.stmts.iter().any(|stmt| matches!(stmt, DslStmt::For { .. })));
        assert!(matches!(
            program.stmts.last(),
            Some(DslStmt::ReturnOrig {
                args: DslOrigArgs::Values(args)
            }) if args.len() == 2
        ));
    }

    #[test]
    fn expression_v2_preserves_direct_call_inference_shape() {
        let program = parse_managed_dsl(
            "let has: boolean = this.containsKey(arg0);\
             let text: java.lang.String = java.lang.String.valueOf(arg1);\
             return text;",
        )
        .unwrap();

        let [DslStmt::Let {
            value: DslValue::Call(receiver_call),
            ..
        }, DslStmt::Let {
            value: DslValue::Call(static_call),
            ..
        }, _] = program.stmts.as_slice()
        else {
            panic!("expected receiver and static direct calls");
        };
        assert_eq!(receiver_call.method_name, "containsKey");
        assert_eq!(receiver_call.sig, "");
        assert!(matches!(receiver_call.target.as_ref(), Some(DslTarget::This)));
        assert_eq!(static_call.class_name.as_deref(), Some("java.lang.String"));
        assert_eq!(static_call.method_name, "valueOf");
        assert_eq!(static_call.sig, "");
    }

    #[test]
    fn expression_v2_preserves_explicit_overload_disambiguation() {
        let program = parse_managed_dsl("return this.get.overload(\"java.lang.Object\")(arg0);").unwrap();
        let [DslStmt::ReturnValue {
            value: Some(DslValue::Call(call)),
        }] = program.stmts.as_slice()
        else {
            panic!("expected overload call");
        };
        assert_eq!(call.method_name, "get");
        assert_eq!(call.sig, "(Ljava/lang/Object;)");
    }

    #[test]
    fn expression_v2_parses_constructor_args_without_explicit_overload() {
        let program = parse_managed_dsl(
            "let sb: java.lang.StringBuilder = new java.lang.StringBuilder(\"rf\");\
             let obj: java.lang.StringBuilder = java.lang.StringBuilder.$new(arg0);",
        )
        .unwrap();
        let [DslStmt::Let {
            value:
                DslValue::NewObject {
                    ctor_sig: first_sig,
                    args: first_args,
                    ..
                },
            ..
        }, DslStmt::Let {
            value:
                DslValue::NewObject {
                    ctor_sig: second_sig,
                    args: second_args,
                    ..
                },
            ..
        }] = program.stmts.as_slice()
        else {
            panic!("expected constructor lets");
        };
        assert_eq!(first_sig, &None);
        assert_eq!(first_args.len(), 1);
        assert_eq!(second_sig, &None);
        assert_eq!(second_args.len(), 1);
    }

    #[test]
    fn expression_v2_parses_new_statement_through_expression_path() {
        let program = parse_managed_dsl("new int[3]; let a: int[] = new int[this.size()];").unwrap();
        assert_eq!(program.stmts.len(), 2);
        assert!(matches!(program.stmts[0], DslStmt::NewArray { .. }));
        assert!(matches!(
            &program.stmts[1],
            DslStmt::Let {
                value: DslValue::NewArray { .. },
                ..
            }
        ));
    }

    #[test]
    fn expression_v2_preserves_legacy_new_array_size_call() {
        let program = parse_managed_dsl("let a: int[] = new int[](this.size());").unwrap();
        assert!(matches!(
            &program.stmts[0],
            DslStmt::Let {
                value: DslValue::NewArray { .. },
                ..
            }
        ));
    }

    #[test]
    fn expression_v2_parses_multidimensional_arrays_and_nested_literals() {
        let program = parse_managed_dsl(
            "let grid: int[][] = [[1, 2], [3, 4]];\
             let refs: java.lang.Object[][] = [[arg0, null], [arg1, this]];\
             let top: int[][] = new int[2][];\
             return grid[1][0];",
        )
        .unwrap();

        assert_eq!(program.stmts.len(), 4);
        assert!(matches!(
            &program.stmts[0],
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::ArrayLiteral { .. },
                ..
            } if type_name == "int[][]"
        ));
        assert!(matches!(
            &program.stmts[1],
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::ArrayLiteral { .. },
                ..
            } if type_name == "java.lang.Object[][]"
        ));
        assert!(matches!(
            &program.stmts[2],
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::NewArray { array_type_name, .. },
                ..
            } if type_name == "int[][]" && array_type_name == "int[][]"
        ));
        assert!(matches!(
            &program.stmts[3],
            DslStmt::ReturnValue {
                value: Some(DslValue::ArrayGet { .. })
            }
        ));
    }

    #[test]
    fn expression_v2_parses_var_empty_statements_and_default_locals() {
        let program = parse_managed_dsl(
            ";;var obj: java.lang.Object;\
             let i: int;\
             for (var j: int = 0; j < 2; j++) { ; i += j; }\
             return obj;",
        )
        .unwrap();

        assert_eq!(program.stmts.len(), 4);
        assert!(matches!(
            &program.stmts[0],
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::DefaultValue { type_name: default_type },
                ..
            } if type_name == "java.lang.Object" && default_type == "java.lang.Object"
        ));
        assert!(matches!(
            &program.stmts[1],
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::DefaultValue { type_name: default_type },
                ..
            } if type_name == "int" && default_type == "int"
        ));
        assert!(matches!(&program.stmts[2], DslStmt::For { .. }));
        assert!(matches!(
            &program.stmts[3],
            DslStmt::ReturnValue {
                value: Some(DslValue::Target(DslTarget::Local(name)))
            } if name.contains("obj")
        ));
    }

    #[test]
    fn expression_v2_rejects_untyped_default_local() {
        let err = match parse_managed_dsl("let x;") {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        };
        assert!(
            err.contains("uninitialized local declarations require an explicit type"),
            "{err}"
        );
    }

    #[test]
    fn expression_v2_infers_string_concat() {
        let program = parse_managed_dsl(
            "let n: int = 3;\
             let prefix: java.lang.String = \"n=\";\
             let text: java.lang.String = prefix + n + \", ok=\" + true;\
             return text;",
        )
        .unwrap();

        let locals = super::super::semantic::validate_semantics(
            std::ptr::null_mut(),
            &program,
            false,
            "Ljava/util/HashMap;".to_string(),
            vec!["Ljava/lang/Object;".to_string(), "Ljava/lang/Object;".to_string()],
            "Ljava/lang/String;".to_string(),
        )
        .unwrap();

        assert!(locals.values().any(|desc| desc == "Ljava/lang/String;"));
        assert!(matches!(
            &program.stmts[2],
            DslStmt::Let {
                value: DslValue::IntBinOp {
                    op: DslIntBinOp::Add,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn expression_v2_scopes_locals_inside_multidimensional_array_indexes() {
        let program = parse_managed_dsl(
            "let n: int = 0;let grid: int[][] = [[1, 2], [3, 4]];\
let picked: int = grid[(n & 1)][0];let refs: java.lang.Object[][] = [[arg0, null], [arg1, this]];\
let ref0: java.lang.Object = refs[(picked & 1)][0];return ref0;",
        )
        .unwrap();

        let DslStmt::Let { name: picked_name, .. } = &program.stmts[2] else {
            panic!("expected picked local declaration");
        };
        let DslStmt::Let {
            value: DslValue::ArrayGet { array, .. },
            ..
        } = &program.stmts[4]
        else {
            panic!("expected ref0 array get");
        };
        let DslValue::ArrayGet { index, .. } = array.as_ref() else {
            panic!("expected nested refs[index] array get");
        };
        let DslValue::IntBinOp { left, .. } = index.as_ref() else {
            panic!("expected picked & 1 index");
        };
        assert!(matches!(
            left.as_ref(),
            DslValue::Target(DslTarget::Local(local)) if local == picked_name
        ));
    }

    #[test]
    fn expression_v2_validates_chained_multidimensional_array_access() {
        let program = parse_managed_dsl(
            "count(\"managed-multidim\");let n: int = this.size();let grid: int[][] = [[1, 2], [3, 4]];\
let picked: int = grid[(n & 1)][0];let refs: java.lang.Object[][] = [[arg0, null], [arg1, this]];\
let ref0: java.lang.Object = refs[(picked & 1)][0];let top: int[][] = new int[2][];\
top[0] = grid[0];if (top.length > 0 && ref0 != null) { java.lang.String.valueOf(ref0); }return ref0;",
        )
        .unwrap();

        let locals = super::super::semantic::validate_semantics(
            std::ptr::null_mut(),
            &program,
            false,
            "Ljava/util/HashMap;".to_string(),
            vec!["Ljava/lang/Object;".to_string(), "Ljava/lang/Object;".to_string()],
            "Ljava/lang/Object;".to_string(),
        )
        .unwrap();

        assert_eq!(locals.get("grid").map(String::as_str), Some("[[I"));
        assert_eq!(locals.get("refs").map(String::as_str), Some("[[Ljava/lang/Object;"));
        assert_eq!(locals.get("picked").map(String::as_str), Some("I"));
        assert_eq!(locals.get("ref0").map(String::as_str), Some("Ljava/lang/Object;"));
        assert_eq!(locals.get("top").map(String::as_str), Some("[[I"));
    }

    #[test]
    fn expression_v2_reports_inner_syntax_error_without_fallback() {
        let err = match parse_managed_dsl("return this.size(;") {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        };
        assert!(err.contains("expected expression"), "{err}");
    }

    #[test]
    fn expression_v2_reports_trailing_tail_without_fallback() {
        let err = match parse_managed_dsl("return this.size()();") {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        };
        assert!(err.contains("unsupported expression tail"), "{err}");
    }
}
