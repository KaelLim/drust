wit_bindgen::generate!({ path: "../../../../sdk/edge-function-template/wit", world: "edge-function" });
struct F;
impl Guest for F {
    fn handle(e: String) -> Result<String, String> {
        // Infinite CPU-bound loop to prove the epoch deadline kills it.
        // `black_box` on every iteration's accumulator AND the exit test
        // stops LLVM (-Os + LTO) from proving the loop's fixed point and
        // constant-folding the whole thing to a single return — which is
        // exactly what a plain `loop { x = x.wrapping_add(1); if x == MAX ...}`
        // does at this opt level. The exit value is seeded from runtime
        // input the compiler cannot know, so the loop is genuinely unbounded.
        let mut x: u64 = std::hint::black_box(e.len() as u64);
        loop {
            x = std::hint::black_box(x.wrapping_add(1));
            // Unreachable in practice: the seed is small and never reaches 0
            // by wrapping in finite time; black_box keeps it from folding.
            if std::hint::black_box(x) == 0 {
                return Ok(x.to_string());
            }
        }
    }
}
export!(F);
