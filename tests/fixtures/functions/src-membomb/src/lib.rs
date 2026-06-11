wit_bindgen::generate!({ path: "../../../../sdk/edge-function-template/wit", world: "edge-function" });
struct F;
impl Guest for F {
    fn handle(_e: String) -> Result<String, String> {
        let mut v: Vec<Vec<u8>> = Vec::new();
        loop {
            v.push(vec![0u8; 16 * 1024 * 1024]); // 16 MiB per step
            if v.len() > 100_000 { return Ok(v.len().to_string()); }
        }
    }
}
export!(F);
