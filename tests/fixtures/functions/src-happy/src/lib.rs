wit_bindgen::generate!({ path: "../../../../sdk/edge-function-template/wit", world: "edge-function" });
struct F;
impl Guest for F {
    fn handle(event_json: String) -> Result<String, String> {
        host::log("info", "happy fixture running");
        host::insert_record("fn_out", &format!(r#"{{"payload":{}}}"#,
            serde_json::to_string(&event_json).unwrap()))?;
        Ok(r#"{"done":true}"#.into())
    }
}
export!(F);
