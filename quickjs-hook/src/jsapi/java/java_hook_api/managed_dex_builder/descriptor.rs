pub(super) fn java_class_to_descriptor(class_name: &str) -> Result<String, String> {
    let trimmed = class_name.trim();
    if trimmed.is_empty() {
        return Err("empty Java class name".to_string());
    }
    if trimmed.starts_with('[') {
        validate_descriptor(trimmed, false)?;
        return Ok(trimmed.to_string());
    }
    if trimmed.ends_with("[]") {
        return java_array_type_to_descriptor(trimmed);
    }
    if trimmed.starts_with('L') && trimmed.ends_with(';') {
        return Ok(trimmed.to_string());
    }
    if trimmed.contains('/') {
        return Ok(format!("L{};", trimmed.trim_matches(';')));
    }
    Ok(format!("L{};", trimmed.replace('.', "/")))
}

fn validate_descriptor(desc: &str, allow_void: bool) -> Result<(), String> {
    let mut pos = 0usize;
    parse_descriptor_at(desc, &mut pos, allow_void)?;
    if pos != desc.len() {
        return Err(format!("invalid descriptor '{}': trailing input", desc));
    }
    Ok(())
}

fn primitive_descriptor(type_name: &str, allow_void: bool) -> Option<&'static str> {
    match type_name {
        "void" | "V" if allow_void => Some("V"),
        "boolean" | "Z" => Some("Z"),
        "byte" | "B" => Some("B"),
        "char" | "C" => Some("C"),
        "short" | "S" => Some("S"),
        "int" | "I" => Some("I"),
        "long" | "J" => Some("J"),
        "float" | "F" => Some("F"),
        "double" | "D" => Some("D"),
        _ => None,
    }
}

fn java_array_type_to_descriptor(type_name: &str) -> Result<String, String> {
    let mut base = type_name.trim();
    let mut dims = 0usize;
    while let Some(stripped) = base.strip_suffix("[]") {
        dims += 1;
        base = stripped.trim();
    }
    if dims == 0 {
        return Err(format!("not an array type '{}'", type_name));
    }
    if base.is_empty() {
        return Err(format!("invalid array type '{}'", type_name));
    }
    let base_desc = if let Some(desc) = primitive_descriptor(base, false) {
        desc.to_string()
    } else {
        java_class_to_descriptor(base)?
    };
    if base_desc == "V" {
        return Err("void[] is not a valid Java array type".to_string());
    }
    let mut out = String::with_capacity(dims + base_desc.len());
    for _ in 0..dims {
        out.push('[');
    }
    out.push_str(&base_desc);
    Ok(out)
}

pub(super) fn parse_method_signature(sig: &str) -> Result<(Vec<String>, String), String> {
    let bytes = sig.as_bytes();
    if bytes.first().copied() != Some(b'(') {
        return Err(format!("invalid method signature '{}': missing '('", sig));
    }

    let mut params = Vec::new();
    let mut pos = 1usize;
    while pos < bytes.len() && bytes[pos] != b')' {
        let start = pos;
        parse_descriptor_at(sig, &mut pos, false)?;
        params.push(sig[start..pos].to_string());
    }
    if pos >= bytes.len() || bytes[pos] != b')' {
        return Err(format!("invalid method signature '{}': missing ')'", sig));
    }
    pos += 1;
    let ret_start = pos;
    parse_descriptor_at(sig, &mut pos, true)?;
    if pos != bytes.len() {
        return Err(format!("invalid method signature '{}': trailing input", sig));
    }
    Ok((params, sig[ret_start..pos].to_string()))
}

pub(super) fn parse_method_params_signature(sig: &str) -> Result<Vec<String>, String> {
    let bytes = sig.as_bytes();
    if bytes.first().copied() != Some(b'(') {
        return Err(format!("invalid method parameter signature '{}': missing '('", sig));
    }

    let mut params = Vec::new();
    let mut pos = 1usize;
    while pos < bytes.len() && bytes[pos] != b')' {
        let start = pos;
        parse_descriptor_at(sig, &mut pos, false)?;
        params.push(sig[start..pos].to_string());
    }
    if pos >= bytes.len() || bytes[pos] != b')' {
        return Err(format!("invalid method parameter signature '{}': missing ')'", sig));
    }
    pos += 1;
    if pos != bytes.len() {
        return Err(format!("invalid method parameter signature '{}': trailing input", sig));
    }
    Ok(params)
}

pub(super) fn parse_call_params(sig: &str) -> Result<Vec<String>, String> {
    match parse_method_signature(sig) {
        Ok((params, _)) => Ok(params),
        Err(_) => parse_method_params_signature(sig),
    }
}

pub(super) fn build_params_sig(params: &[String]) -> String {
    let mut sig = String::from("(");
    for param in params {
        sig.push_str(param);
    }
    sig.push(')');
    sig
}

fn parse_descriptor_at(sig: &str, pos: &mut usize, allow_void: bool) -> Result<(), String> {
    let bytes = sig.as_bytes();
    if *pos >= bytes.len() {
        return Err("unexpected end of descriptor".to_string());
    }
    match bytes[*pos] {
        b'V' if allow_void => {
            *pos += 1;
            Ok(())
        }
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
            *pos += 1;
            Ok(())
        }
        b'L' => {
            *pos += 1;
            while *pos < bytes.len() && bytes[*pos] != b';' {
                *pos += 1;
            }
            if *pos >= bytes.len() {
                return Err("unterminated object descriptor".to_string());
            }
            *pos += 1;
            Ok(())
        }
        b'[' => {
            while *pos < bytes.len() && bytes[*pos] == b'[' {
                *pos += 1;
            }
            parse_descriptor_at(sig, pos, false)
        }
        other => Err(format!("invalid descriptor char '{}'", other as char)),
    }
}

pub(super) fn descriptor_word_count(desc: &str) -> u16 {
    if desc == "J" || desc == "D" {
        2
    } else {
        1
    }
}

pub(super) fn descriptor_list_word_count(descs: &[String]) -> Result<u16, String> {
    let mut total = 0u16;
    for desc in descs {
        total = total
            .checked_add(descriptor_word_count(desc))
            .ok_or_else(|| "too many dex registers".to_string())?;
    }
    Ok(total)
}

pub(super) fn build_method_sig(params: &[String], return_type: &str) -> String {
    let mut sig = String::from("(");
    for param in params {
        sig.push_str(param);
    }
    sig.push(')');
    sig.push_str(return_type);
    sig
}

pub(super) fn return_is_object(return_type: &str) -> bool {
    return_type.starts_with('L') || return_type.starts_with('[')
}

pub(super) fn array_component_descriptor(array_desc: &str) -> Result<String, String> {
    array_desc
        .strip_prefix('[')
        .map(|desc| desc.to_string())
        .ok_or_else(|| format!("expected array descriptor, got {}", array_desc))
}

pub(super) fn descriptor_to_java_class_name(desc: &str) -> Result<String, String> {
    let Some(class_desc) = desc.strip_prefix('L').and_then(|value| value.strip_suffix(';')) else {
        return Err(format!(
            "method overload resolution requires object class, got {}",
            desc
        ));
    };
    Ok(class_desc.replace('/', "."))
}

pub(super) fn java_class_to_descriptor_or_primitive(type_name: &str) -> Result<String, String> {
    let trimmed = type_name.trim();
    if trimmed.starts_with('[') {
        validate_descriptor(trimmed, false)?;
        return Ok(trimmed.to_string());
    }
    if trimmed.ends_with("[]") {
        return java_array_type_to_descriptor(trimmed);
    }
    if let Some(value) = primitive_descriptor(trimmed, true) {
        return Ok(value.to_string());
    }
    java_class_to_descriptor(trimmed)
}
