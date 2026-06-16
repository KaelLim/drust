---
type: sdk-template
name: edge-function-template
target: wasm32-wasip2
status: wip
updated: 2026-06-10
---

# drust edge-function template

```bash
rustup target add wasm32-wasip2   # one-time
cp -r sdk/edge-function-template my_fn && cd my_fn
cargo build --target wasm32-wasip2 --release
curl -X POST https://drust.example.com/drust/t/<tenant>/functions \
  -H "Authorization: Bearer <service-token>" \
  -F name=my_fn -F wasm=@target/wasm32-wasip2/release/edge_function_template.wasm \
  -F 'triggers=[{"collection":"posts","events":["created"]}]' -F 'description=…'
```

Host API surface: see `wit/world.wit`. No outbound network, no filesystem —
only the imported host functions, scoped to your own tenant.
