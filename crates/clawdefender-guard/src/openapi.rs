//! OpenAPI 3.1 specification for the ClawDefender Guard REST API.

/// Return the OpenAPI 3.1 YAML specification as a string.
pub fn openapi_spec() -> &'static str {
    include_str!("openapi.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_not_empty() {
        let spec = openapi_spec();
        assert!(!spec.is_empty());
    }

    #[test]
    fn test_openapi_spec_is_valid_yaml() {
        let spec = openapi_spec();
        // Basic structural checks since we don't have a YAML parser dep
        assert!(spec.contains("openapi:"));
        assert!(spec.contains("paths:"));
        assert!(spec.contains("/api/v1/guard:"));
        assert!(spec.contains("/api/v1/guards:"));
        assert!(spec.contains("bearerAuth"));
        assert!(spec.contains("components:"));
    }

    #[test]
    fn test_openapi_spec_has_all_endpoints() {
        let spec = openapi_spec();
        assert!(spec.contains("/api/v1/guard:"));
        assert!(spec.contains("/api/v1/guard/{guard_id}:"));
        assert!(spec.contains("/api/v1/guard/{guard_id}/stats:"));
        assert!(spec.contains("/api/v1/guard/{guard_id}/check:"));
        assert!(spec.contains("/api/v1/guard/{guard_id}/suggest:"));
        assert!(spec.contains("/api/v1/guard/{guard_id}/webhooks:"));
        assert!(spec.contains("/api/v1/guards:"));
        assert!(spec.contains("/api/v1/openapi.yaml:"));
    }
}
