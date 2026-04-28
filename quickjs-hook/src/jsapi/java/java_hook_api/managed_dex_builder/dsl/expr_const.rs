use super::*;
use token_stream::DslTokenStream;

const CONST_INT_BINARY_TOKEN_OPS: &[(&str, DslIntBinOp, u8)] = &[
    (">>>", DslIntBinOp::Ushr, 5),
    ("<<", DslIntBinOp::Shl, 5),
    (">>", DslIntBinOp::Shr, 5),
];

const CONST_INT_BINARY_CHAR_OPS: &[(char, DslIntBinOp, u8)] = &[
    ('|', DslIntBinOp::Or, 1),
    ('^', DslIntBinOp::Xor, 2),
    ('&', DslIntBinOp::And, 3),
    ('+', DslIntBinOp::Add, 6),
    ('-', DslIntBinOp::Sub, 6),
    ('*', DslIntBinOp::Mul, 7),
    ('/', DslIntBinOp::Div, 7),
    ('%', DslIntBinOp::Rem, 7),
];

impl<'a> DslParser<'a> {
    pub(super) fn try_parse_const_expr_v2(&mut self) -> Option<DslValue> {
        let start = self.pos;
        let mut stream = DslTokenStream::new(self.input, &self.tokens, self.pos);
        let value = parse_const_int_binary_expr(&mut stream, 0).ok()?;
        if has_postfix_start(&stream) {
            self.pos = start;
            return None;
        }
        self.pos = stream.pos();
        Some(value)
    }
}

fn parse_const_int_binary_expr(stream: &mut DslTokenStream<'_>, min_prec: u8) -> Result<DslValue, String> {
    let mut left = parse_const_unary_expr(stream)?;
    loop {
        let Some((op, prec)) = peek_const_int_binary_op(stream) else {
            break;
        };
        if prec < min_prec {
            break;
        }
        consume_const_int_binary_op(stream, op)?;
        let right = parse_const_int_binary_expr(stream, prec + 1)?;
        left = fold_int_binop(op, left, right);
    }
    Ok(left)
}

fn parse_const_unary_expr(stream: &mut DslTokenStream<'_>) -> Result<DslValue, String> {
    if stream.consume_char('-') {
        if matches!(stream.current_kind(), Some(DslTokenKind::Number(_))) {
            return Ok(DslValue::Int(stream.parse_i16_after_sign(true)?));
        }
        let value = parse_const_unary_expr(stream)?;
        return Ok(fold_unary_op(DslUnaryOp::Neg, value));
    }
    if stream.consume_char('~') {
        let value = parse_const_unary_expr(stream)?;
        return Ok(fold_unary_op(DslUnaryOp::BitNot, value));
    }
    if stream.consume_char('!') {
        let value = parse_const_unary_expr(stream)?;
        return Ok(fold_unary_op(DslUnaryOp::BoolNot, value));
    }
    parse_const_primary_expr(stream)
}

fn parse_const_primary_expr(stream: &mut DslTokenStream<'_>) -> Result<DslValue, String> {
    match stream.current_kind() {
        Some(DslTokenKind::Number(_)) => Ok(DslValue::Int(stream.parse_i16_after_sign(false)?)),
        Some(DslTokenKind::Ident(value)) if value == "true" => {
            stream.advance();
            Ok(DslValue::Bool(true))
        }
        Some(DslTokenKind::Ident(value)) if value == "false" => {
            stream.advance();
            Ok(DslValue::Bool(false))
        }
        Some(DslTokenKind::Ident(value)) if value == "null" => {
            stream.advance();
            Ok(DslValue::Null)
        }
        Some(DslTokenKind::String(value)) => {
            let value = value.clone();
            stream.advance();
            Ok(DslValue::String(value))
        }
        Some(DslTokenKind::Symbol('(')) => {
            stream.advance();
            let value = parse_const_int_binary_expr(stream, 0)?;
            if !stream.consume_char(')') {
                return Err(stream.err("expected ')'"));
            }
            Ok(value)
        }
        _ => Err(stream.err("not a constant expression")),
    }
}

fn peek_const_int_binary_op(stream: &DslTokenStream<'_>) -> Option<(DslIntBinOp, u8)> {
    for (token, op, prec) in CONST_INT_BINARY_TOKEN_OPS {
        if stream.peek_op(token) {
            return Some((*op, *prec));
        }
    }
    CONST_INT_BINARY_CHAR_OPS
        .iter()
        .find_map(|(ch, op, prec)| stream.peek_char(*ch).then_some((*op, *prec)))
}

fn consume_const_int_binary_op(stream: &mut DslTokenStream<'_>, op: DslIntBinOp) -> Result<(), String> {
    if let Some((token, _, _)) = CONST_INT_BINARY_TOKEN_OPS
        .iter()
        .find(|(_, candidate, _)| *candidate == op)
    {
        if stream.consume_op(token) {
            return Ok(());
        }
    }
    if let Some((ch, _, _)) = CONST_INT_BINARY_CHAR_OPS
        .iter()
        .find(|(_, candidate, _)| *candidate == op)
    {
        if stream.consume_char(*ch) {
            return Ok(());
        }
    }
    Err(stream.err("unsupported integer binary operator"))
}

fn has_postfix_start(stream: &DslTokenStream<'_>) -> bool {
    stream.peek_char('.') || stream.peek_char('[') || stream.peek_op("?.") || stream.peek_ident("as")
}
