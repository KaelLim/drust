---
type: sdk-template
name: edge-function-template
target: wasm32-wasip2
status: wip
updated: 2026-07-14
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

Host API surface: see `wit/world.wit`. No filesystem — only the imported host
functions, scoped to your own tenant. Outbound HTTP is available via
`host::http_fetch`, but ONLY to origins the tenant's service key has added to
the egress allowlist (`system=function`); every fetch also passes the private-IP
block, and redirects are returned to you un-followed.
