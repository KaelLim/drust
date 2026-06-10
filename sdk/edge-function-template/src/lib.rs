wit_bindgen::generate!({ path: "wit", world: "edge-function" });

struct EdgeFn;

impl Guest for EdgeFn {
    /// Called once per matching event. `event_json` is one of:
    ///   {"trigger":"record.created","collection":"posts","record":{…}}
    ///   {"trigger":"record.updated","collection":"posts","record":{…}}
    ///   {"trigger":"record.deleted","collection":"posts","id":42}
    ///   {"trigger":"file.uploaded","key":"…","size_bytes":1,"visibility":"private","content_type":"…"}
    /// Return Ok(json-string) to record a result, Err(msg) to record an error.
    fn handle(event_json: String) -> Result<String, String> {
        let ev: serde_json::Value =
            serde_json::from_str(&event_json).map_err(|e| format!("bad event: {e}"))?;
        host::log("info", &format!("trigger = {}", ev["trigger"]));
        // Example: write a derived row.
        // host::insert_record("derived", r#"{"src":"hello"}"#)?;
        Ok(r#"{"ok":true}"#.to_string())
    }
}

export!(EdgeFn);
