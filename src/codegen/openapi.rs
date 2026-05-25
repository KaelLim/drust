//! v1.27 — OpenAPI 3.1 renderer. Output is a serde_json::Value the
//! caller can serialise. Validates by parse-back in the route handler
//! and by golden-file test in tests/codegen_golden.rs.

use super::ir::{CodegenIr, CollectionIr, FieldIr, FieldType, DefaultValue};
use super::filter_ast_schema::filter_ast_openapi_schema;
use serde_json::{json, Value};

pub fn render_openapi(ir: &CodegenIr) -> Value {
    let mut paths = serde_json::Map::new();
    let mut schemas = serde_json::Map::new();

    // FilterAst shared component.
    schemas.insert("FilterAst".into(), filter_ast_openapi_schema());

    for coll in &ir.collections {
        let row_name = pascal(&coll.name);
        let insert_name = format!("{row_name}Insert");
        let update_name = format!("{row_name}Update");

        schemas.insert(row_name.clone(), collection_row_schema(coll));
        schemas.insert(insert_name.clone(), collection_insert_schema(coll));
        schemas.insert(update_name.clone(), collection_update_schema(coll));

        let base = format!("/t/{}/records/{}", ir.tenant_id, coll.name);
        paths.insert(
            base.clone(),
            json!({
                "get": list_op(&coll.name, &row_name),
                "post": insert_op(&insert_name, &row_name),
            }),
        );
        paths.insert(
            format!("{base}/{{id}}"),
            json!({
                "get": get_op(&coll.name, &row_name),
                "put": update_op(&update_name, &row_name),
                "delete": delete_op(&coll.name),
            }),
        );
        // POST /collections/<c>/list — FilterAst body
        paths.insert(
            format!("/t/{}/collections/{}/list", ir.tenant_id, coll.name),
            json!({ "post": list_filter_op(&row_name) }),
        );
        if coll.has_vector {
            paths.insert(
                format!("/t/{}/collections/{}/search", ir.tenant_id, coll.name),
                json!({ "post": search_op(coll, &row_name) }),
            );
        }
        if coll.realtime_enabled {
            paths.insert(
                format!("/t/{}/records/{}/subscribe", ir.tenant_id, coll.name),
                json!({ "get": subscribe_op(&coll.name, &row_name) }),
            );
        }
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": format!("drust tenant {}", ir.tenant_id),
            "version": "1.0"
        },
        "servers": [{ "url": ir.base_url }],
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "BearerAuth": { "type": "http", "scheme": "bearer" }
            }
        },
        "security": [{ "BearerAuth": [] }],
        "paths": paths
    })
}

// --- helpers ---------------------------------------------------------

fn pascal(s: &str) -> String {
    s.split('_').filter(|p| !p.is_empty()).map(|p| {
        let mut chars = p.chars();
        chars.next().map(|c| c.to_ascii_uppercase()).into_iter().chain(chars).collect::<String>()
    }).collect()
}

fn collection_row_schema(coll: &CollectionIr) -> Value {
    let mut props = serde_json::Map::new();
    let mut required = Vec::new();
    for f in &coll.fields {
        props.insert(f.name.clone(), field_schema(f));
        if !f.nullable && !f.server_managed {
            required.push(Value::String(f.name.clone()));
        }
    }
    let mut obj = serde_json::Map::new();
    obj.insert("type".into(), Value::String("object".into()));
    obj.insert("properties".into(), Value::Object(props));
    if !required.is_empty() {
        obj.insert("required".into(), Value::Array(required));
    }
    if let Some(d) = &coll.description {
        obj.insert("description".into(), Value::String(d.clone()));
    }
    Value::Object(obj)
}

fn collection_insert_schema(coll: &CollectionIr) -> Value {
    let mut props = serde_json::Map::new();
    let mut required = Vec::new();
    for f in &coll.fields {
        if f.server_managed { continue; }
        props.insert(f.name.clone(), field_schema(f));
        if !f.nullable && f.default.is_none() {
            required.push(Value::String(f.name.clone()));
        }
    }
    json!({ "type": "object", "properties": props, "required": required })
}

fn collection_update_schema(coll: &CollectionIr) -> Value {
    let mut props = serde_json::Map::new();
    for f in &coll.fields {
        if f.server_managed { continue; }
        props.insert(f.name.clone(), field_schema(f));
    }
    // No required[] — every field optional on update.
    json!({ "type": "object", "properties": props })
}

fn field_schema(f: &FieldIr) -> Value {
    let mut s = serde_json::Map::new();
    match &f.ty {
        FieldType::Text => { s.insert("type".into(), Value::String("string".into())); }
        FieldType::Integer => { s.insert("type".into(), Value::String("integer".into())); }
        FieldType::Real => { s.insert("type".into(), Value::String("number".into())); }
        FieldType::Blob => {
            s.insert("type".into(), Value::String("string".into()));
            s.insert("format".into(), Value::String("binary".into()));
        }
        FieldType::Json => {} // free-form
        FieldType::Boolean => { s.insert("type".into(), Value::String("boolean".into())); }
        FieldType::Vector { dim } => {
            s.insert("type".into(), Value::String("array".into()));
            s.insert("items".into(), json!({ "type": "number" }));
            s.insert("minItems".into(), json!(dim));
            s.insert("maxItems".into(), json!(dim));
        }
    }
    if f.nullable {
        // OpenAPI 3.1: type can be a list including "null".
        if let Some(t) = s.get("type").cloned() {
            s.insert("type".into(), json!([t, "null"]));
        }
    }
    if let Some(d) = &f.default {
        match d {
            DefaultValue::Literal(v) => { s.insert("default".into(), v.clone()); }
            DefaultValue::SqlExpr(_) => {
                s.insert("readOnly".into(), Value::Bool(true));
                s.insert("description".into(), Value::String(
                    f.description.clone().unwrap_or_else(|| "Server-generated on insert.".into())
                ));
            }
        }
    }
    if let Some(fk) = &f.fk {
        let suffix = format!("Foreign key to `{}`.", fk);
        let combined = match &f.description {
            Some(d) => format!("{d} {suffix}"),
            None => suffix,
        };
        s.insert("description".into(), Value::String(combined));
    } else if let Some(d) = &f.description {
        s.insert("description".into(), Value::String(d.clone()));
    }
    Value::Object(s)
}

fn insert_op(insert_name: &str, row_name: &str) -> Value {
    json!({
        "summary": format!("Insert into {row_name}"),
        "requestBody": {
            "required": true,
            "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{insert_name}") } } }
        },
        "responses": {
            "200": { "description": "Created", "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{row_name}") } } } }
        }
    })
}

fn list_op(_coll: &str, row_name: &str) -> Value {
    json!({
        "summary": format!("List {row_name} (simple)"),
        "responses": {
            "200": { "description": "OK", "content": { "application/json": { "schema": {
                "type": "object",
                "properties": {
                    "items": { "type": "array", "items": { "$ref": format!("#/components/schemas/{row_name}") } },
                    "total": { "type": "integer" }
                }
            }}}}
        }
    })
}

fn list_filter_op(row_name: &str) -> Value {
    json!({
        "summary": format!("List {row_name} with FilterAst"),
        "requestBody": {
            "required": false,
            "content": { "application/json": { "schema": {
                "type": "object",
                "properties": {
                    "filter": { "$ref": "#/components/schemas/FilterAst" },
                    "sort": { "type": "array", "items": { "type": "string" } },
                    "page": { "type": "integer" },
                    "per_page": { "type": "integer" }
                }
            }}}
        },
        "responses": {
            "200": { "description": "OK", "content": { "application/json": { "schema": {
                "type": "object",
                "properties": {
                    "items": { "type": "array", "items": { "$ref": format!("#/components/schemas/{row_name}") } },
                    "total": { "type": "integer" }
                }
            }}}}
        }
    })
}

fn get_op(_coll: &str, row_name: &str) -> Value {
    json!({
        "summary": format!("Get one {row_name}"),
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }],
        "responses": {
            "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{row_name}") } } } },
            "404": { "description": "Not found" }
        }
    })
}

fn update_op(update_name: &str, row_name: &str) -> Value {
    json!({
        "summary": format!("Update {row_name}"),
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }],
        "requestBody": {
            "required": true,
            "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{update_name}") } } }
        },
        "responses": {
            "200": { "description": "Updated", "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{row_name}") } } } }
        }
    })
}

fn delete_op(_coll: &str) -> Value {
    json!({
        "summary": "Delete by id",
        "parameters": [
            { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } },
            { "name": "dry_run", "in": "query", "required": false, "schema": { "type": "boolean" } }
        ],
        "responses": {
            "200": { "description": "Deleted (or blast radius if dry_run=true)" },
            "404": { "description": "Not found" }
        }
    })
}

fn search_op(coll: &CollectionIr, row_name: &str) -> Value {
    let vec_fields: Vec<String> = coll.fields.iter()
        .filter_map(|f| matches!(f.ty, FieldType::Vector { .. }).then(|| f.name.clone()))
        .collect();
    json!({
        "summary": format!("Vector similarity search over {row_name}"),
        "requestBody": {
            "required": true,
            "content": { "application/json": { "schema": {
                "type": "object",
                "required": ["field", "vector", "k"],
                "properties": {
                    "field": { "type": "string", "enum": vec_fields },
                    "vector": { "type": "array", "items": { "type": "number" } },
                    "k": { "type": "integer" },
                    "metric": { "type": "string", "enum": ["cosine", "l2"] }
                }
            }}}
        },
        "responses": {
            "200": { "description": "OK", "content": { "application/json": { "schema": {
                "type": "array",
                "items": {
                    "allOf": [
                        { "$ref": format!("#/components/schemas/{row_name}") },
                        { "type": "object", "properties": { "_distance": { "type": "number" } } }
                    ]
                }
            }}}}
        }
    })
}

fn subscribe_op(_coll: &str, row_name: &str) -> Value {
    json!({
        "summary": format!("SSE stream of {row_name} mutations"),
        "responses": {
            "200": { "description": "text/event-stream of JSON events" }
        }
    })
}
