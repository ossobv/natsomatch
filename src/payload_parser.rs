use serde_json::{Value, from_slice};


pub fn get_section(payload: &[u8]) -> Box<str> {
    // FIXME: This is probably way slower than it could be. We could do manual json searching for
    // .attributes.section instead.
    // FIXME: We probably explode if we get invalid payload.
    // b"{\"attributes\":{\"host\":\"...\",\"job\":\"...\",\"section\":\"some-section\"},...
    let json_bytes: &[u8] = payload;
    let result: Result<Value, _> = from_slice(json_bytes);
    match result {
        Ok(value) => {
            return value
                .get("attributes").expect("missing attributes")
                .get("section").expect("missing section")
                .as_str().expect("invalid section")
                .into();
        }
        Err(_) => {
            return "_".into();
        }
    }
}

#[allow(dead_code)]
pub fn get_section2(payload: &[u8]) -> Box<str> {
    let payload_str = std::str::from_utf8(payload).unwrap();
    if let Some(start_index) = payload_str.find(r#""section":"#) {
        let start_index = start_index + r#""section":"#.len();
        if let Some(end_index) = payload_str[start_index..].find('"') {
            return payload_str[start_index..start_index + end_index].into();
        }
    }
    "_".into()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_section() {
        let jsb = br#"{"attributes":{"something":"more_something","section":"the_section"},"other":true}"#;
        assert_eq!(&*get_section(jsb), "the_section");
    }

    #[test]
    fn test_get_section2() {
        let jsb = br#"{"attributes":{"something":"more_something","section":"the_section"},"other":true}"#;
        assert_eq!(&*get_section2(jsb), "the_section");
    }
}
