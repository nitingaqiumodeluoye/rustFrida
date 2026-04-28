use super::*;

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn single_or_block(mut stmts: Vec<DslStmt>) -> DslStmt {
    if stmts.len() == 1 {
        stmts.remove(0)
    } else {
        DslStmt::Block(stmts)
    }
}
