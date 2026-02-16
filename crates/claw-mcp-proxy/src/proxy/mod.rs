//! Protocol proxy implementations (stdio, HTTP).

pub mod http;
pub mod stdio;

pub use http::HttpProxy;
pub use stdio::StdioProxy;
