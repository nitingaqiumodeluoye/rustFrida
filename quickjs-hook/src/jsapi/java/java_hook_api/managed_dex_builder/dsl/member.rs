use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_postfix_member_value(
        &mut self,
        receiver: DslValue,
        null_safe: bool,
    ) -> Result<DslValue, String> {
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
            let checkpoint = self.mark();
            self.expect_char('.')?;
            if self.peek_ident("interface") {
                self.expect_ident("interface")?;
                self.skip_ws();
                DslCallKind::Interface
            } else {
                self.restore(checkpoint);
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

    pub(super) fn parse_js_member_value(&mut self, first: String) -> Result<DslValue, String> {
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
}
