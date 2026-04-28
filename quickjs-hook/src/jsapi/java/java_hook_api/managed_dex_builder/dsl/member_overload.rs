use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_postfix_overload_call(
        &mut self,
        receiver: DslValue,
        method_name: String,
        call_kind: DslCallKind,
        null_safe: bool,
    ) -> Result<DslValue, String> {
        let overload_args = self.parse_overload_selector_args()?;
        let args = self.parse_overload_call_args()?;
        let (class_name, params) = self.resolve_postfix_overload_sig(call_kind, &overload_args)?;

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

    pub(super) fn parse_js_overload_member_value(&mut self, mut parts: Vec<String>) -> Result<DslValue, String> {
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

        let overload_args = self.parse_overload_selector_args()?;
        let args = self.parse_overload_call_args()?;

        if parts.len() == 1 && self.scoped_target_name(&parts[0]).is_some() {
            let target = self.scoped_target_name(&parts[0]).unwrap();
            let (class_name, params) = self.resolve_target_overload_sig(&target, call_kind, &overload_args)?;
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
            let params = self.resolve_static_overload_sig(&overload_args)?;
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

    fn parse_overload_selector_args(&mut self) -> Result<Vec<String>, String> {
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
        Ok(overload_args)
    }

    fn parse_overload_call_args(&mut self) -> Result<Vec<DslValue>, String> {
        self.skip_ws();
        self.expect_char('(')?;
        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;
        Ok(args)
    }

    fn resolve_postfix_overload_sig(
        &self,
        call_kind: DslCallKind,
        overload_args: &[String],
    ) -> Result<(Option<String>, String), String> {
        if call_kind == DslCallKind::Interface {
            return self.resolve_interface_overload_sig(overload_args);
        }
        if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
            if overload_args.len() != 1 {
                return Err(self.err("full-signature overload expects overload(\"sig\")"));
            }
            return Ok((None, overload_args[0].clone()));
        }
        if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
            return Ok((Some(overload_args[0].clone()), overload_args[1].clone()));
        }
        Ok((None, overload_params_sig(overload_args)?))
    }

    fn resolve_target_overload_sig(
        &self,
        target: &DslTarget,
        call_kind: DslCallKind,
        overload_args: &[String],
    ) -> Result<(Option<String>, String), String> {
        if call_kind == DslCallKind::Interface {
            return self.resolve_interface_overload_sig(overload_args);
        }
        if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
            return Ok((None, overload_args[0].clone()));
        }
        if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
            return Ok((Some(overload_args[0].clone()), overload_args[1].clone()));
        }

        let first_is_explicit_class = matches!(target, DslTarget::Last | DslTarget::Result)
            && overload_args.len() >= 2
            && overload_args[0].contains('.');
        if first_is_explicit_class {
            return Ok((
                Some(overload_args[0].clone()),
                overload_params_sig(&overload_args[1..])?,
            ));
        }
        Ok((None, overload_params_sig(overload_args)?))
    }

    fn resolve_static_overload_sig(&self, overload_args: &[String]) -> Result<String, String> {
        if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
            if overload_args.len() != 1 {
                return Err(self.err("static full-signature overload expects overload(\"sig\")"));
            }
            return Ok(overload_args[0].clone());
        }
        overload_params_sig(overload_args)
    }

    fn resolve_interface_overload_sig(&self, overload_args: &[String]) -> Result<(Option<String>, String), String> {
        let Some(class_name) = overload_args.first() else {
            return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
        };
        if class_name.starts_with('(') {
            return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
        }
        let params = if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
            overload_args[1].clone()
        } else {
            overload_params_sig(&overload_args[1..])?
        };
        Ok((Some(class_name.clone()), params))
    }
}

fn overload_params_sig(overload_args: &[String]) -> Result<String, String> {
    let param_types = overload_args
        .iter()
        .map(|arg| java_class_to_descriptor_or_primitive(arg))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(build_params_sig(&param_types))
}
