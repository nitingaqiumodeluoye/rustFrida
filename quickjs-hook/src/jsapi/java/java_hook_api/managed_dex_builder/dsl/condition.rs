use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_js_condition(&mut self) -> Result<DslCondition, String> {
        self.parse_js_or_condition()
    }

    pub(super) fn parse_js_if_condition(&mut self) -> Result<DslCondition, String> {
        let checkpoint = self.pos;
        if let Ok(value) = self.parse_value_arg() {
            self.skip_ws();
            if self.peek() == Some(')') {
                return Ok(value.into_bool_condition());
            }
        }
        self.pos = checkpoint;

        let condition = self.parse_js_condition()?;
        self.skip_ws();
        if self.peek() == Some('?') {
            self.expect_char('?')?;
            let then_value = self.parse_value_arg()?;
            self.expect_char(':')?;
            let else_value = self.parse_value_arg()?;
            return Ok(fold_ternary(condition, then_value, else_value).into_bool_condition());
        }
        Ok(condition)
    }

    fn parse_js_or_condition(&mut self) -> Result<DslCondition, String> {
        let mut condition = self.parse_js_and_condition()?;
        loop {
            self.skip_ws();
            if !self.peek_op("||") {
                break;
            }
            self.expect_op("||")?;
            let right = self.parse_js_and_condition()?;
            condition = condition_or(condition, right);
        }
        Ok(condition)
    }

    fn parse_js_and_condition(&mut self) -> Result<DslCondition, String> {
        let mut condition = self.parse_js_unary_condition()?;
        loop {
            self.skip_ws();
            if !self.peek_op("&&") {
                break;
            }
            self.expect_op("&&")?;
            let right = self.parse_js_unary_condition()?;
            condition = condition_and(condition, right);
        }
        Ok(condition)
    }

    fn parse_js_unary_condition(&mut self) -> Result<DslCondition, String> {
        self.skip_ws();
        if self.peek() == Some('!') {
            self.expect_char('!')?;
            return Ok(condition_not(self.parse_js_unary_condition()?));
        }
        if self.peek() == Some('(') {
            self.expect_char('(')?;
            let condition = self.parse_js_condition()?;
            self.expect_char(')')?;
            return Ok(condition);
        }
        self.parse_js_condition_leaf()
    }

    fn parse_js_condition_leaf(&mut self) -> Result<DslCondition, String> {
        let left = self.parse_non_ternary_value_arg()?;
        self.skip_ws();
        if self.peek_ident("instanceof") {
            self.expect_ident("instanceof")?;
            let class_name = self.parse_type_name()?;
            return Ok(DslCondition::InstanceOf {
                value: left,
                class_name,
            });
        }
        if !self.peek_js_cmp_op() {
            if let DslValue::Bool(value) = left {
                return Ok(DslCondition::Const(value));
            }
            return Ok(DslCondition::Bool { value: left });
        }
        let op = self.parse_js_cmp_op()?;
        let right = self.parse_non_ternary_value_arg()?;
        let left_is_null = matches!(left, DslValue::Null);
        let right_is_null = matches!(right, DslValue::Null);
        if right_is_null {
            return match op {
                IfCmpOp::Eq => Ok(DslCondition::Null {
                    value: left,
                    invert: false,
                }),
                IfCmpOp::Ne => Ok(DslCondition::Null {
                    value: left,
                    invert: true,
                }),
                _ => Err(self.err("null condition only supports == and !=")),
            };
        }
        if left_is_null {
            return match op {
                IfCmpOp::Eq => Ok(DslCondition::Null {
                    value: right,
                    invert: false,
                }),
                IfCmpOp::Ne => Ok(DslCondition::Null {
                    value: right,
                    invert: true,
                }),
                _ => Err(self.err("null condition only supports == and !=")),
            };
        }
        Ok(DslCondition::Cmp { op, left, right })
    }

    fn parse_js_cmp_op(&mut self) -> Result<IfCmpOp, String> {
        self.skip_ws();
        if self.peek_op("==") {
            self.expect_op("==")?;
            Ok(IfCmpOp::Eq)
        } else if self.peek_op("!=") {
            self.expect_op("!=")?;
            Ok(IfCmpOp::Ne)
        } else if self.peek_op("<=") {
            self.expect_op("<=")?;
            Ok(IfCmpOp::Le)
        } else if self.peek_op(">=") {
            self.expect_op(">=")?;
            Ok(IfCmpOp::Ge)
        } else if self.peek() == Some('<') {
            self.pos += 1;
            Ok(IfCmpOp::Lt)
        } else if self.peek() == Some('>') {
            self.pos += 1;
            Ok(IfCmpOp::Gt)
        } else {
            Err(self.err("expected comparison operator"))
        }
    }

    fn peek_js_cmp_op(&mut self) -> bool {
        self.skip_ws();
        self.peek_op("==")
            || self.peek_op("!=")
            || self.peek_op("<=")
            || self.peek_op(">=")
            || self.peek() == Some('<')
            || self.peek() == Some('>')
    }
}
