///
/// We put a lot of trust in the JSON provided by grafana-agent-flow and
/// passed along by Vector. Because it should be the same always, we're
/// confident that we can parse the json blob as a simple string,
/// instead of going full fledged serde_json on it. This saves us many
/// precious microseconds.
///
/// (1) We expect the {"attributes":{ map to be first.
/// (2) We expect no excess spaces.
/// (3) The fields inside the "attributes" map should have no funny
///     characters, like "section":"section\"ha, there is more".
/// (4) I don't think you can abuse it enough to spoil other hosts logs,
///     but you could spoil/break your own log parsing. But if you wanted
///     to do that, you might as well just stop the grafana-agent.
///

pub struct Attributes<'a> {
    // FIXME: Do we need these public?
    // {"attributes":{"...":"...","section":"the_section",...
    pub attributes: &'a [u8],
    pub hostname: &'a [u8],
    pub timestamp: &'a [u8],
    pub section: &'a [u8],
}

impl<'a> Attributes<'a> {
    pub fn from_payload(payload: &[u8]) -> Attributes {
        let attributes = get_attributes(payload); // 60ns

        // There is a lot of speed to gain here, if we wanted.
        let hostname = get_jsonmap_strval(attributes, b"\"host\":\""); // 150ns
        let timestamp = get_jsonmap_strval(payload, b"\"timestamp\":\""); // 150ns (FIXME, too broad)
        let section = get_jsonmap_strval(attributes, b"\"section\":\""); // 150ns

        Attributes {
            attributes: attributes,
            hostname: hostname,
            timestamp: timestamp,
            section: section,
        }
    }

    pub fn get_unique_id(&self) -> String {
        format!(
            "{}H{}", std::str::from_utf8(self.timestamp).unwrap(),
            std::str::from_utf8(self.hostname).unwrap())
    }

    pub fn get_section(&self) -> &str {
        std::str::from_utf8(self.section).unwrap()
    }
}

pub struct Attributes2 {
    pub hostname: String,
    pub timestamp: String,
    pub section: String,
}

impl Attributes2 {
    pub fn from_payload(payload: &[u8]) -> Attributes2 {
        let res: serde_json::Value = serde_json::from_slice(payload).unwrap();
        let h = res["attributes"]["host"].as_str().unwrap();
        let t = res["timestamp"].as_str().unwrap();
        let s = res["attributes"]["section"].as_str().unwrap();

        Attributes2 {
            hostname: h.to_string(),
            timestamp: t.to_string(),
            section: s.to_string(),
        }
    }

    pub fn get_unique_id(&self) -> String {
        format!("{}H{}", self.timestamp, self.hostname)
    }

    pub fn get_section(&self) -> &str {
        self.section.as_ref()
    }
}

#[allow(dead_code)]
pub fn get_section_safe(payload: &[u8]) -> Box<str> {
    // We expect payload to look like this:
    //   {"attributes":{"...":"...","section":"the_section",...
    // We want "the_section".
    let json_bytes: &[u8] = payload;
    let result: Result<serde_json::Value, _> = serde_json::from_slice(json_bytes);
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
pub fn get_section_fast(payload: &[u8]) -> &str {
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
    std::str::from_utf8(slice).unwrap()
}

fn get_jsonmap_strval<'a>(jsonmap: &'a [u8], needle: &'a [u8]) -> &'a [u8] {
    // jsonmap: {"foo":"bar","key":"value"}
    // needle:  "key":"
    // value:   value
    // rest:    "}
    let val_begin: usize;
    match memmem(&jsonmap, needle) {
        Some(idx) => { val_begin = idx + needle.len() },
        None => { return b"ERR_no_key"; },
    }
    let val_end: usize;
    match memchr(&jsonmap[val_begin..], b'"') {
        Some(idx) => { val_end = val_begin + idx; }
        None => { return b"ERR_no_val_end_dq"; },
    }
    let slice = &jsonmap[val_begin..val_end];
    slice
}

pub fn get_attributes(payload: &[u8]) -> &[u8] {
    let attr_start: usize;
    match memmem(payload, br#"{"attributes":{"#) {  // length 15
        Some(idx) => { attr_start = 15 + idx; }
        None => { return b"ERR_attributes_missing"; }
    }
    if attr_start != 15 {
        // If it's not the first element, then we cannot be certain that
        // this is in fact "the" attributes we're after.
        return b"ERR_attributes_not_at_0";
    }
    let mut attr_end: usize = 0;
    for i in 15..=(payload.len() - 1) {
        if payload[i] == b'{' {
            return b"ERR_attributes_has_map";
        }
        if payload[i] == b'}' {
            attr_end = i;
            break;
        }
    }
    if attr_end == 0 {
        return b"ERR_attributes_has_no_end";
    }
    return &payload[(attr_start - 1)..(attr_end + 1)]
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
    fn test_struct() {
        let jsb = br#"{"attributes":{"filename":"/var/log/auth.log","host":"mgmt.example","section":"SCT","job":"loki","systemd_unit":"ssh.service"},"message":"foobarbaz","timestamp":"2024-02-16T15:45:16.266891180Z"}"#;
        let pl = Attributes::from_payload(jsb);
        assert_eq!(pl.attributes, br#"{"filename":"/var/log/auth.log","host":"mgmt.example","section":"SCT","job":"loki","systemd_unit":"ssh.service"}"#);
        assert_eq!(pl.hostname, br#"mgmt.example"#);
        assert_eq!(pl.get_section(), "SCT");
        assert_eq!(pl.get_unique_id(), "2024-02-16T15:45:16.266891180ZHmgmt.example");
        assert_eq!(pl.timestamp, br#"2024-02-16T15:45:16.266891180Z"#);
    }

    #[test]
    fn test_struct2() {
        let jsb = br#"{"attributes":{"filename":"/var/log/auth.log","host":"mgmt.example","section":"SCT","job":"loki","systemd_unit":"ssh.service"},"message":"foobarbaz","timestamp":"2024-02-16T15:45:16.266891180Z"}"#;
        let pl = Attributes2::from_payload(jsb);
        assert_eq!(pl.hostname, "mgmt.example");
        assert_eq!(pl.get_section(), "SCT");
        assert_eq!(pl.get_unique_id(), "2024-02-16T15:45:16.266891180ZHmgmt.example");
        assert_eq!(pl.timestamp, "2024-02-16T15:45:16.266891180Z");
    }

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

    #[test]
    fn test_get_attributes() {
        let jsb = br#"{"attributes":{"something":"more_something","section":"the_section"},"other":true}"#;
        assert_eq!(&*get_attributes(jsb), br#"{"something":"more_something","section":"the_section"}"#);
    }
}
