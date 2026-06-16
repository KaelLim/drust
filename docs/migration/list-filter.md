# Migrating from GET `?filter` / `?sort` to POST `/list`

> **Sunset:** Fri, 01 Jan 2027 00:00:00 GMT.
> After this date, GET `/t/<id>/records/<coll>` will refuse requests
> that carry `?filter=` or `?sort=` raw query parameters.

## Why this is changing

`GET /t/<id>/records/<coll>?filter=<raw SQL fragment>` interpolates the
client-supplied string verbatim into a SQLite WHERE clause. User-token
callers on owner-scoped collections can use SQL comments (`--`) to
neutralise the `owner_field` row-level enforcement, which would expose
other users' rows. drust v1.19.2 added a typed rejection
(`USER_FILTER_DENIED_ON_OWNER_SCOPED`) for that specific case, but the
raw-SQL surface remains fundamentally injection-shaped.

drust v1.21 introduced POST `/t/<id>/collections/<coll>/list` with a
structured `FilterAst` body. drust compiles the AST into parameterised
SQL with `?` binds, so:

- `owner_field` is enforced by construction (an auto-appended
  `"<field>" = ?` clause that user-supplied filter cannot bypass).
- There is no string interpolation, no SQL-comment escape, no raw-SQL
  attack surface.

H5-1 phase 1 ships in v1.29.6 with informational `Deprecation` +
`Sunset` headers; phase 2 (after the sunset above) refuses the legacy
params with `400 LEGACY_PARAM_REMOVED`.

## What to change

### Before — GET with raw `?filter` / `?sort`

```bash
curl "https://drust.example.com/t/blog/records/posts?\
filter=published=1%20AND%20author_id=%27u-abc%27&\
sort=-created_at&\
page=2&per_page=20" \
  -H "Authorization: Bearer drust_anon_..."
```

### After — POST `/list` with structured `FilterAst`

```bash
curl -X POST "https://drust.example.com/t/blog/collections/posts/list" \
  -H "Authorization: Bearer drust_anon_..." \
  -H "Content-Type: application/json" \
  -d '{
    "filter": {
      "and": [
        {"published": true},
        {"author_id": "u-abc"}
      ]
    },
    "sort": {"field": "created_at", "dir": "desc"},
    "page": 2,
    "per_page": 20
  }'
```

Response shape:

```json
{"records": [...], "total": <int>, "page": <int>, "perPage": <int>}
```

> **Note:** POST `/list` does NOT return `totalPages` (the legacy GET `/records` does).
> Compute it client-side as `Math.ceil(total / perPage)` if your UI needs it.

## FilterAst quick reference

| Operator        | JSON shape                                       | SQL                  |
|-----------------|--------------------------------------------------|----------------------|
| eq (shorthand)  | `{"field": value}`                               | `field = ?`          |
| eq              | `{"field": {"eq": value}}`                       | `field = ?`          |
| ne              | `{"field": {"ne": value}}`                       | `field != ?`         |
| gt              | `{"field": {"gt": value}}`                       | `field > ?`          |
| gte             | `{"field": {"gte": value}}`                      | `field >= ?`         |
| lt              | `{"field": {"lt": value}}`                       | `field < ?`          |
| lte             | `{"field": {"lte": value}}`                      | `field <= ?`         |
| like            | `{"field": {"like": "%pat%"}}`                   | `field LIKE ?`       |
| in              | `{"field": {"in": [v1, v2, ...]}}`               | `field IN (?,?,...)` |
| nin             | `{"field": {"nin": [v1, v2, ...]}}`              | `field NOT IN (?,?,...)` |
| is_null         | `{"field": {"is_null": true}}`                   | `field IS NULL`      |
| is_not_null     | `{"field": {"is_not_null": true}}`               | `field IS NOT NULL`  |
| and             | `{"and": [clause1, clause2, ...]}`               | `clause AND clause`  |
| or              | `{"or": [clause1, clause2, ...]}`                | `clause OR clause`   |
| not             | `{"not": clause}`                                | `NOT (clause)`       |

(Note: the operand for `is_null` / `is_not_null` is ignored by the AST but must be a JSON value — `true` is conventional.)

Full grammar: see `src/query/vector_filter.rs::FilterAst` (Rust source) or
fetch `GET /t/<id>/openapi.json` for the generated JSON-schema view of
the filter shape (`src/codegen/filter_ast_schema.rs`).

## Permissions matrix

| Role    | GET ?filter (legacy)           | POST /list                  |
|---------|--------------------------------|-----------------------------|
| Anon    | Allowed when `anon_caps.select` | Allowed when `anon_caps.select` |
| User    | Allowed unless owner-scoped (`USER_FILTER_DENIED_ON_OWNER_SCOPED`) | Allowed, owner_filter auto-applied |
| Service | Allowed                         | Allowed, bypasses owner_filter |

POST `/list` strictly improves over `?filter` for User tokens — drust
guarantees owner_filter enforcement by construction; raw SQL never
could.

## Timeline

| Date         | Behavior                                       |
|--------------|------------------------------------------------|
| 2026-05-29   | v1.29.6 ships — informational deprecation     |
| 2026-05-29   | v1.29.7 ships — Sunset day-name fixed, Link to this doc, CORS exposed |
| 2027-01-01   | v1.30+ phase 2 — `?filter` / `?sort` return `400 LEGACY_PARAM_REMOVED` |

## Questions

Open a GitHub issue against
[KaelLim/drust](https://github.com/KaelLim/drust/issues) and reference
this migration.
