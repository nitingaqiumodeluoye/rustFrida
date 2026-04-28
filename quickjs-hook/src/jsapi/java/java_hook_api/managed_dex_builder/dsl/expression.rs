use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_value_arg(&mut self) -> Result<DslValue, String> {
        self.parse_ternary_expr()
    }

    pub(super) fn parse_non_ternary_value_arg(&mut self) -> Result<DslValue, String> {
        self.parse_int_binary_expr(0)
    }

    fn parse_ternary_expr(&mut self) -> Result<DslValue, String> {
        let checkpoint = self.pos;
        if let Ok(condition) = self.parse_js_condition() {
            self.skip_ws();
            if self.peek() == Some('?') {
                self.expect_char('?')?;
                let then_value = self.parse_value_arg()?;
                self.expect_char(':')?;
                let else_value = self.parse_value_arg()?;
                return Ok(fold_ternary(condition, then_value, else_value));
            }
        }
        self.pos = checkpoint;
        self.parse_int_binary_expr(0)
    }

    fn parse_int_binary_expr(&mut self, min_prec: u8) -> Result<DslValue, String> {
        let mut left = self.parse_value_unary()?;
        loop {
            self.skip_ws();
            let Some((op, prec)) = self.peek_int_binary_op() else {
                break;
            };
            if prec < min_prec {
                break;
            }
            self.consume_int_binary_op(op)?;
            let right = self.parse_int_binary_expr(prec + 1)?;
            left = fold_int_binop(op, left, right);
        }
        Ok(left)
    }

    fn parse_value_unary(&mut self) -> Result<DslValue, String> {
        self.skip_ws();
        if self.peek() == Some('-') {
            self.expect_char('-')?;
            if self.peek_number() {
                self.pos = self.pos.saturating_sub(1);
                return Ok(DslValue::Int(self.parse_i16()?));
            }
            let value = self.parse_value_unary()?;
            return Ok(fold_unary_op(DslUnaryOp::Neg, value));
        }
        if self.peek() == Some('~') {
            self.expect_char('~')?;
            let value = self.parse_value_unary()?;
            return Ok(fold_unary_op(DslUnaryOp::BitNot, value));
        }
        if self.peek() == Some('!') {
            self.expect_char('!')?;
            let value = self.parse_value_unary()?;
            return Ok(fold_unary_op(DslUnaryOp::BoolNot, value));
        }
        self.parse_value_primary()
    }

    fn parse_value_primary(&mut self) -> Result<DslValue, String> {
        self.skip_ws();
        let value = if self.peek_string() {
            DslValue::String(self.parse_string()?)
        } else if self.peek_number() {
            DslValue::Int(self.parse_i16()?)
        } else if self.peek() == Some('(') {
            self.expect_char('(')?;
            let value = self.parse_value_arg()?;
            self.expect_char(')')?;
            value
        } else if self.peek() == Some('[') {
            self.parse_array_literal()?
        } else {
            let ident = self.parse_ident()?;
            if ident == "null" {
                DslValue::Null
            } else if ident == "true" {
                DslValue::Bool(true)
            } else if ident == "false" {
                DslValue::Bool(false)
            } else {
                self.parse_value_from_ident(ident)?
            }
        };
        self.skip_ws();
        self.parse_value_postfix(value)
    }

    fn peek_int_binary_op(&mut self) -> Option<(DslIntBinOp, u8)> {
        self.skip_ws();
        if self.peek_op(">>>") {
            return Some((DslIntBinOp::Ushr, 5));
        }
        if self.peek_op("<<") {
            return Some((DslIntBinOp::Shl, 5));
        }
        if self.peek_op(">>") {
            return Some((DslIntBinOp::Shr, 5));
        }
        match self.peek()? {
            '|' => Some((DslIntBinOp::Or, 1)),
            '^' => Some((DslIntBinOp::Xor, 2)),
            '&' => Some((DslIntBinOp::And, 3)),
            '+' => Some((DslIntBinOp::Add, 6)),
            '-' => Some((DslIntBinOp::Sub, 6)),
            '*' => Some((DslIntBinOp::Mul, 7)),
            '/' => Some((DslIntBinOp::Div, 7)),
            '%' => Some((DslIntBinOp::Rem, 7)),
            _ => None,
        }
    }

    fn consume_int_binary_op(&mut self, op: DslIntBinOp) -> Result<(), String> {
        match op {
            DslIntBinOp::Ushr => self.expect_op(">>>"),
            DslIntBinOp::Shl => self.expect_op("<<"),
            DslIntBinOp::Shr => self.expect_op(">>"),
            DslIntBinOp::Or => self.expect_char('|'),
            DslIntBinOp::Xor => self.expect_char('^'),
            DslIntBinOp::And => self.expect_char('&'),
            DslIntBinOp::Add => self.expect_char('+'),
            DslIntBinOp::Sub => self.expect_char('-'),
            DslIntBinOp::Mul => self.expect_char('*'),
            DslIntBinOp::Div => self.expect_char('/'),
            DslIntBinOp::Rem => self.expect_char('%'),
        }
    }

    pub(super) fn parse_value_from_ident(&mut self, ident: String) -> Result<DslValue, String> {
        self.skip_ws();
        if ident == "orig" && self.peek() == Some('(') {
            return Ok(DslValue::OrigCall(self.parse_orig_args()?));
        }
        let value = if self.peek() == Some('.') {
            self.parse_js_member_value(ident)?
        } else {
            let target = self.scoped_target_name(&ident);
            let target = target.unwrap_or_else(|| DslTarget::Local(ident));
            DslValue::Target(target)
        };
        self.parse_value_postfix(value)
    }

    fn parse_array_literal(&mut self) -> Result<DslValue, String> {
        self.expect_char('[')?;
        let mut elements = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(']') {
                self.expect_char(']')?;
                break;
            }
            elements.push(self.parse_value_arg()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.expect_char(',')?;
                    self.skip_ws();
                    if self.peek() == Some(']') {
                        self.expect_char(']')?;
                        break;
                    }
                }
                Some(']') => {
                    self.expect_char(']')?;
                    break;
                }
                _ => return Err(self.err("array literal expects ',' or ']'")),
            }
        }
        Ok(DslValue::ArrayLiteral { elements })
    }

    fn parse_value_postfix(&mut self, mut value: DslValue) -> Result<DslValue, String> {
        loop {
            self.skip_ws();
            if self.peek_ident("as") {
                self.expect_ident("as")?;
                let class_name = self.parse_type_name()?;
                value = DslValue::Cast {
                    value: Box::new(value),
                    class_name,
                };
            } else if self.peek() == Some('[') {
                self.expect_char('[')?;
                let index = self.parse_value_arg()?;
                let type_name = if self.peek() == Some(':') {
                    self.expect_char(':')?;
                    Some(self.parse_type_name()?)
                } else {
                    None
                };
                self.expect_char(']')?;
                value = DslValue::ArrayGet {
                    array: Box::new(value),
                    index: Box::new(index),
                    type_name,
                };
            } else if self.peek_op("?.") {
                value = self.parse_postfix_member_value(value, true)?;
            } else if self.peek() == Some('.') {
                value = self.parse_postfix_member_value(value, false)?;
            } else {
                return Ok(value);
            }
        }
    }

    fn parse_postfix_member_value(&mut self, receiver: DslValue, null_safe: bool) -> Result<DslValue, String> {
        if null_safe {
            self.expect_op("?.")?;
        } else {
            self.expect_char('.')?;
        }
        let member_name = self.parse_ident()?;
        self.skip_ws();

        if member_name == "length" && self.peek() != Some('(') && self.peek() != Some('.') {
            return Ok(DslValue::ArrayLength(Box::new(receiver)));
        }
        if member_name == "$new" {
            return Err(self.err("$new is only supported on class names"));
        }

        let call_kind = if self.peek() == Some('.') {
            let checkpoint = self.pos;
            self.expect_char('.')?;
            if self.peek_ident("interface") {
                self.expect_ident("interface")?;
                self.skip_ws();
                DslCallKind::Interface
            } else {
                self.pos = checkpoint;
                DslCallKind::Virtual
            }
        } else {
            DslCallKind::Virtual
        };

        if self.peek() == Some('.') {
            self.expect_char('.')?;
            self.expect_ident("overload")?;
            return self.parse_postfix_overload_call(receiver, member_name, call_kind, null_safe);
        }

        if self.peek() != Some('(') {
            if call_kind == DslCallKind::Interface {
                return Err(self.err("interface field access is not supported"));
            }
            return Ok(DslValue::FieldGet {
                stmt: Box::new(DslFieldStmt {
                    target: None,
                    receiver: Some(Box::new(receiver)),
                    class_name: None,
                    field_name: member_name,
                    type_name: String::new(),
                    value: None,
                }),
                is_static: false,
            });
        }

        self.expect_char('(')?;
        match self.parse_member_call_args(true, false)? {
            ParsedCallArgs::Direct(args) => Ok(DslValue::Call(DslCallStmt {
                kind: call_kind,
                target: None,
                receiver: Some(Box::new(receiver)),
                null_safe,
                class_name: None,
                method_name: member_name,
                sig: String::new(),
                args,
            })),
            ParsedCallArgs::LegacyCall { class_name, sig, args } => Ok(DslValue::Call(DslCallStmt {
                kind: call_kind,
                target: None,
                receiver: Some(Box::new(receiver)),
                null_safe,
                class_name,
                method_name: member_name,
                sig,
                args,
            })),
            ParsedCallArgs::Field { type_name, .. } => {
                if call_kind == DslCallKind::Interface {
                    return Err(self.err("interface field access is not supported"));
                }
                Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: None,
                        receiver: Some(Box::new(receiver)),
                        class_name: None,
                        field_name: member_name,
                        type_name,
                        value: None,
                    }),
                    is_static: false,
                })
            }
        }
    }

    fn parse_postfix_overload_call(
        &mut self,
        receiver: DslValue,
        method_name: String,
        call_kind: DslCallKind,
        null_safe: bool,
    ) -> Result<DslValue, String> {
        self.expect_char('(')?;
        self.skip_ws();
        let mut overload_args = Vec::new();
        if self.peek() != Some(')') {
            loop {
                overload_args.push(self.parse_string_arg()?);
                if self.peek() != Some(',') {
                    break;
                }
                self.expect_char(',')?;
                self.skip_ws();
            }
        }
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char('(')?;
        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;

        let (class_name, params) = if call_kind == DslCallKind::Interface {
            let Some(class_name) = overload_args.first() else {
                return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
            };
            if class_name.starts_with('(') {
                return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
            }
            let params = if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
                overload_args[1].clone()
            } else {
                let param_types = overload_args[1..]
                    .iter()
                    .map(|arg| java_class_to_descriptor_or_primitive(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                build_params_sig(&param_types)
            };
            (Some(class_name.clone()), params)
        } else if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
            if overload_args.len() != 1 {
                return Err(self.err("full-signature overload expects overload(\"sig\")"));
            }
            (None, overload_args[0].clone())
        } else if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
            (Some(overload_args[0].clone()), overload_args[1].clone())
        } else {
            let param_types = overload_args
                .iter()
                .map(|arg| java_class_to_descriptor_or_primitive(arg))
                .collect::<Result<Vec<_>, _>>()?;
            (None, build_params_sig(&param_types))
        };

        Ok(DslValue::Call(DslCallStmt {
            kind: call_kind,
            target: None,
            receiver: Some(Box::new(receiver)),
            null_safe,
            class_name,
            method_name,
            sig: params,
            args,
        }))
    }

    fn parse_member_call_args(
        &mut self,
        allow_field: bool,
        allow_explicit_class: bool,
    ) -> Result<ParsedCallArgs, String> {
        self.skip_ws();
        if self.peek() == Some(')') {
            self.expect_char(')')?;
            return Ok(ParsedCallArgs::Direct(Vec::new()));
        }

        if self.peek_string() {
            let first = self.parse_string_arg()?;
            self.skip_ws();
            if first.starts_with('(') {
                let args = self.parse_optional_value_args()?;
                self.expect_char(')')?;
                return Ok(ParsedCallArgs::LegacyCall {
                    class_name: None,
                    sig: first,
                    args,
                });
            }
            if allow_explicit_class && self.peek() == Some(',') && looks_like_type_name(&first) {
                let checkpoint = self.pos;
                self.expect_char(',')?;
                self.skip_ws();
                if self.peek_string() {
                    let second = self.parse_string_arg()?;
                    if second.starts_with('(') {
                        let args = self.parse_optional_value_args()?;
                        self.expect_char(')')?;
                        return Ok(ParsedCallArgs::LegacyCall {
                            class_name: Some(first),
                            sig: second,
                            args,
                        });
                    }
                }
                self.pos = checkpoint;
            }
            if allow_field && self.peek() == Some(')') && looks_like_type_name(&first) {
                self.expect_char(')')?;
                return Ok(ParsedCallArgs::Field {
                    class_name: None,
                    type_name: first,
                });
            }

            let mut args = vec![DslValue::String(first)];
            while self.peek() == Some(',') {
                self.expect_char(',')?;
                args.push(self.parse_value_arg()?);
                self.skip_ws();
            }
            self.expect_char(')')?;
            return Ok(ParsedCallArgs::Direct(args));
        }

        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;
        Ok(ParsedCallArgs::Direct(args))
    }

    fn parse_js_member_value(&mut self, first: String) -> Result<DslValue, String> {
        let mut parts = vec![first];
        while self.peek() == Some('.') {
            self.expect_char('.')?;
            parts.push(self.parse_ident()?);
            self.skip_ws();
            if parts.last().map(|part| part.as_str()) == Some("overload") {
                return self.parse_js_overload_member_value(parts);
            }
        }
        if parts.len() < 2 {
            return Err(self.err("expected member access"));
        }
        if parts.last().map(|part| part.as_str()) == Some("$new") {
            return self.parse_js_new_member_value(parts);
        }
        if parts.len() == 2 && parts[1] == "length" && self.peek() != Some('(') {
            let target = self
                .scoped_target_name(&parts[0])
                .unwrap_or_else(|| DslTarget::Local(parts[0].clone()));
            return Ok(DslValue::ArrayLength(Box::new(DslValue::Target(target))));
        }
        if self.peek() != Some('(') {
            if parts.len() == 2 && !looks_like_static_class_name(&parts[0]) {
                let target = self
                    .scoped_target_name(&parts[0])
                    .unwrap_or_else(|| DslTarget::Local(parts[0].clone()));
                return Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: Some(target),
                        receiver: None,
                        class_name: None,
                        field_name: parts[1].clone(),
                        type_name: String::new(),
                        value: None,
                    }),
                    is_static: false,
                });
            }
            return Err(
                self.err("direct field access currently supports only instance fields on this/arg/local values")
            );
        }
        self.expect_char('(')?;

        if parts.len() == 2 && self.scoped_target_name(&parts[0]).is_some() {
            let target = self.scoped_target_name(&parts[0]).unwrap();
            match self.parse_member_call_args(true, matches!(target, DslTarget::Last | DslTarget::Result))? {
                ParsedCallArgs::Direct(args) => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Virtual,
                    target: Some(target),
                    receiver: None,
                    null_safe: false,
                    class_name: None,
                    method_name: parts[1].clone(),
                    sig: String::new(),
                    args,
                })),
                ParsedCallArgs::LegacyCall { class_name, sig, args } => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Virtual,
                    target: Some(target),
                    receiver: None,
                    null_safe: false,
                    class_name,
                    method_name: parts[1].clone(),
                    sig,
                    args,
                })),
                ParsedCallArgs::Field { class_name, type_name } => Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: Some(target),
                        receiver: None,
                        class_name,
                        field_name: parts[1].clone(),
                        type_name,
                        value: None,
                    }),
                    is_static: false,
                }),
            }
        } else {
            let member_name = parts.pop().unwrap();
            let class_name = parts.join(".");
            match self.parse_member_call_args(true, false)? {
                ParsedCallArgs::Direct(args) => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Static,
                    target: None,
                    receiver: None,
                    null_safe: false,
                    class_name: Some(class_name),
                    method_name: member_name,
                    sig: String::new(),
                    args,
                })),
                ParsedCallArgs::LegacyCall { sig, args, .. } => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Static,
                    target: None,
                    receiver: None,
                    null_safe: false,
                    class_name: Some(class_name),
                    method_name: member_name,
                    sig,
                    args,
                })),
                ParsedCallArgs::Field { type_name, .. } => Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: None,
                        receiver: None,
                        class_name: Some(class_name),
                        field_name: member_name,
                        type_name,
                        value: None,
                    }),
                    is_static: true,
                }),
            }
        }
    }

    fn parse_js_new_member_value(&mut self, mut parts: Vec<String>) -> Result<DslValue, String> {
        if parts.len() < 2 || parts.pop().as_deref() != Some("$new") {
            return Err(self.err("expected Class.$new(...)"));
        }
        let class_name = parts.join(".");
        self.expect_char('(')?;
        let (ctor_sig, args) = self.parse_new_constructor_args()?;
        self.expect_char(')')?;
        Ok(DslValue::NewObject {
            class_name,
            ctor_sig,
            args,
        })
    }

    fn parse_js_overload_member_value(&mut self, mut parts: Vec<String>) -> Result<DslValue, String> {
        if parts.len() < 3 || parts.last().map(|part| part.as_str()) != Some("overload") {
            return Err(self.err("expected member.overload(...)"));
        }
        parts.pop();
        let call_kind = if parts.last().map(|part| part.as_str()) == Some("interface") {
            parts.pop();
            DslCallKind::Interface
        } else {
            DslCallKind::Virtual
        };
        let member_name = parts.pop().unwrap();

        self.expect_char('(')?;
        self.skip_ws();
        let mut overload_args = Vec::new();
        if self.peek() != Some(')') {
            loop {
                overload_args.push(self.parse_string_arg()?);
                if self.peek() != Some(',') {
                    break;
                }
                self.expect_char(',')?;
                self.skip_ws();
            }
        }
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char('(')?;
        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;

        if parts.len() == 1 && self.scoped_target_name(&parts[0]).is_some() {
            let target = self.scoped_target_name(&parts[0]).unwrap();
            let (class_name, params) = if call_kind == DslCallKind::Interface {
                let Some(class_name) = overload_args.first() else {
                    return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
                };
                if class_name.starts_with('(') {
                    return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
                }
                let params = if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
                    overload_args[1].clone()
                } else {
                    let param_types = overload_args[1..]
                        .iter()
                        .map(|arg| java_class_to_descriptor_or_primitive(arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    build_params_sig(&param_types)
                };
                (Some(class_name.clone()), params)
            } else if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
                (None, overload_args[0].clone())
            } else if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
                (Some(overload_args[0].clone()), overload_args[1].clone())
            } else {
                let first_is_explicit_class = matches!(target, DslTarget::Last | DslTarget::Result)
                    && overload_args.len() >= 2
                    && overload_args[0].contains('.');
                if first_is_explicit_class {
                    let param_types = overload_args[1..]
                        .iter()
                        .map(|arg| java_class_to_descriptor_or_primitive(arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    (Some(overload_args[0].clone()), build_params_sig(&param_types))
                } else {
                    let param_types = overload_args
                        .iter()
                        .map(|arg| java_class_to_descriptor_or_primitive(arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    (None, build_params_sig(&param_types))
                }
            };
            Ok(DslValue::Call(DslCallStmt {
                kind: call_kind,
                target: Some(target),
                receiver: None,
                null_safe: false,
                class_name,
                method_name: member_name,
                sig: params,
                args,
            }))
        } else {
            if call_kind == DslCallKind::Interface {
                return Err(self.err("interface overload requires an instance target"));
            }
            let params = if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
                if overload_args.len() != 1 {
                    return Err(self.err("static full-signature overload expects overload(\"sig\")"));
                }
                overload_args[0].clone()
            } else {
                let param_types = overload_args
                    .iter()
                    .map(|arg| java_class_to_descriptor_or_primitive(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                build_params_sig(&param_types)
            };
            Ok(DslValue::Call(DslCallStmt {
                kind: DslCallKind::Static,
                target: None,
                receiver: None,
                null_safe: false,
                class_name: Some(parts.join(".")),
                method_name: member_name,
                sig: params,
                args,
            }))
        }
    }

    pub(super) fn parse_value_arg_list_until_close(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                break;
            }
            args.push(self.parse_value_arg()?);
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
        }
        Ok(args)
    }

    fn parse_optional_value_args(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
            args.push(self.parse_value_arg()?);
        }
        Ok(args)
    }
}
