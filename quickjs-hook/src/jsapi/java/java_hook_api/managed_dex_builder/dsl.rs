use super::{build_method_sig, build_params_sig, java_class_to_descriptor_or_primitive, IfCmpOp};

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
mod expr_const;
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
mod token_stream;

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
