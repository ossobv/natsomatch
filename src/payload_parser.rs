#[cfg(test)]
use serde_json::{Value, from_slice};


#[cfg(test)]
#[allow(dead_code)]
pub fn get_section_safe(payload: &[u8]) -> Box<str> {
    // We expect payload to look like this:
    //   {"attributes":{"...":"...","section":"the_section",...
    // We want "the_section".
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
pub fn get_section_fast(payload: &[u8]) -> Box<str> {
    // We expect payload to look like this:
    //   {"attributes":{"...":"...","section":"the_section",...
    // We want "the_section".
    //
    // If someone has the power to reorder the json, then they could manipulate things, but we're
    // pretty confident that we're okay. Especially the {"attributes":{ block should be completely
    // in our hands. So let's confirm.
    if &payload[0..15] != br#"{"attributes":{"# {
        return "ERR_bad_start".into();
    }
    let section_start: usize;
    match memmem(&payload[15..], br#""section":""#) {
        Some(idx) => { section_start = 15 + idx + 11; },
        None => { return "ERR_no_section".into(); },
    }
    let section_end: usize;
    match memchr(&payload[section_start..], b'"') {
        Some(idx) => { section_end = section_start + idx; }
        None => { return "ERR_no_trailing_dq".into(); },
    }
    let slice = &payload[section_start..section_end];
    // We could in fact return the slice here, for another small optimization.
    // But that makes it incompatible with get_section_safe().
    std::str::from_utf8(slice).unwrap().into()
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    // Iterate through the bytes of the haystack
    for i in 0..=(haystack.len() - needle.len()) {
        // Compare the bytes starting from index i
        if &haystack[i..i + needle.len()] == needle {
            return Some(i); // Return the index if the subsequence is found
        }
    }
    None // Return None if the subsequence is not found
}

fn memchr(haystack: &[u8], needle: u8) -> Option<usize> {
    // Iterate through the bytes of the haystack
    for i in 0..=(haystack.len() - 1) {
        // Compare the byte starting from index i
        if haystack[i] == needle {
            return Some(i); // Return the index if the character is found
        }
    }
    None // Return None if the subsequence is not found
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_section_safe() {
        let jsb = br#"{"attributes":{"something":"more_something","section":"the_section"},"other":true}"#;
        assert_eq!(&*get_section_safe(jsb), "the_section");
    }

    #[test]
    fn test_get_section_fast() {
        let jsb = br#"{"attributes":{"something":"more_something","section":"the_section"},"other":true}"#;
        assert_eq!(&*get_section_fast(jsb), "the_section");
    }
}
