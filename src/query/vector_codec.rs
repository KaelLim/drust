//! JSON ↔ packed-f32 BLOB codec for vector fields.
//!
//! Vector fields are stored as BLOB columns of exactly `dim * 4` bytes,
//! holding `dim` little-endian f32 values back-to-back. This is the
//! on-disk format consumed by `sqlite-vec`'s `vec_distance_*`
//! functions, so we don't transform on the way *into* a search query —
//! the BLOB goes straight to the bound parameter.

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum VectorCodecError {
    #[error("vector field {field:?}: expected {expected}-element array, got {got}")]
    DimMismatch {
        field: String,
        expected: u32,
        got: usize,
    },
    #[error("vector field {field:?}: element at index {index} is not a finite number")]
    NonFinite { field: String, index: usize },
    #[error("vector field {field:?}: element at index {index} is not numeric")]
    NotNumeric { field: String, index: usize },
    #[error("vector field {field:?}: input is not a JSON array")]
    NotArray { field: String },
    #[error("vector field {field:?}: stored BLOB length {got} is not a multiple of 4")]
    BadBlobLen { field: String, got: usize },
}

/// Encode a JSON array of numbers as a packed-f32 BLOB of exactly
/// `dim * 4` bytes. Caller supplies the `field` name only for error
/// messages.
pub fn pack(field: &str, dim: u32, v: &Value) -> Result<Vec<u8>, VectorCodecError> {
    let arr = v.as_array().ok_or_else(|| VectorCodecError::NotArray {
        field: field.to_string(),
    })?;
    if arr.len() != dim as usize {
        return Err(VectorCodecError::DimMismatch {
            field: field.to_string(),
            expected: dim,
            got: arr.len(),
        });
    }
    let mut bytes = Vec::with_capacity(arr.len() * 4);
    for (i, n) in arr.iter().enumerate() {
        let f = n.as_f64().ok_or_else(|| VectorCodecError::NotNumeric {
            field: field.to_string(),
            index: i,
        })?;
        if !f.is_finite() {
            return Err(VectorCodecError::NonFinite {
                field: field.to_string(),
                index: i,
            });
        }
        bytes.extend_from_slice(&(f as f32).to_le_bytes());
    }
    Ok(bytes)
}

/// Decode a packed-f32 BLOB back into a JSON array of f32 numbers.
/// Round-trips lossily through f32 — callers see the truncated values.
pub fn unpack(field: &str, blob: &[u8]) -> Result<Value, VectorCodecError> {
    if blob.len() % 4 != 0 {
        return Err(VectorCodecError::BadBlobLen {
            field: field.to_string(),
            got: blob.len(),
        });
    }
    let nums: Vec<Value> = blob
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .map(|f| {
            serde_json::Number::from_f64(f as f64)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        })
        .collect();
    Ok(Value::Array(nums))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pack_then_unpack_preserves_values_at_f32_precision() {
        let v = json!([1.0, 0.5, -0.25, 1.5e-3]);
        let bytes = pack("emb", 4, &v).unwrap();
        assert_eq!(bytes.len(), 16);
        let round = unpack("emb", &bytes).unwrap();
        let arr = round.as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0].as_f64().unwrap(), 1.0);
        assert_eq!(arr[1].as_f64().unwrap(), 0.5);
        assert_eq!(arr[2].as_f64().unwrap(), -0.25);
        let drift = (arr[3].as_f64().unwrap() - 1.5e-3).abs();
        assert!(drift < 1e-6, "drift too large: {drift}");
    }

    #[test]
    fn pack_dim_mismatch_errors() {
        let v = json!([1.0, 2.0]);
        let err = pack("emb", 3, &v).unwrap_err();
        assert!(matches!(err, VectorCodecError::DimMismatch { .. }));
    }

    #[test]
    fn pack_non_array_errors() {
        let v = json!("not an array");
        let err = pack("emb", 1, &v).unwrap_err();
        assert!(matches!(err, VectorCodecError::NotArray { .. }));
    }

    #[test]
    fn pack_non_numeric_errors() {
        let v = json!([1.0, "two", 3.0]);
        let err = pack("emb", 3, &v).unwrap_err();
        assert!(matches!(err, VectorCodecError::NotNumeric { index: 1, .. }));
    }

    #[test]
    fn pack_null_treated_as_non_numeric() {
        // JSON serialisers refuse to construct NaN as a Number; clients
        // that try to send NaN typically marshal it to `null`. We map
        // that to NotNumeric (cleaner UX than a separate "Null" arm).
        let v = json!([1.0, null, 3.0]);
        let err = pack("emb", 3, &v).unwrap_err();
        assert!(matches!(err, VectorCodecError::NotNumeric { index: 1, .. }));
    }

    #[test]
    fn unpack_bad_len_errors() {
        let bad = vec![0u8; 7];
        let err = unpack("emb", &bad).unwrap_err();
        assert!(matches!(err, VectorCodecError::BadBlobLen { got: 7, .. }));
    }
}
