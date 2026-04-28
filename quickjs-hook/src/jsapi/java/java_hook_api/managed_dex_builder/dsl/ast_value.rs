use super::*;

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
