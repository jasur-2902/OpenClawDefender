//! Lightweight axum web server for the post-analysis chat UI.

use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::chat::ChatManager;

/// The chat web server.
pub struct ChatServer {
    chat_manager: Arc<ChatManager>,
    port: u16,
}

#[derive(Clone)]
struct AppState {
    chat_manager: Arc<ChatManager>,
}

#[derive(Deserialize)]
struct SendMessageRequest {
    message: String,
}

#[derive(Serialize)]
struct SendMessageResponse {
    content: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

#[derive(Serialize)]
struct SessionInfo {
    session_id: String,
    event_id: String,
    event_summary: String,
    swarm_verdict: String,
    messages: Vec<MessageInfo>,
}

#[derive(Serialize)]
struct MessageInfo {
    role: String,
    content: String,
    timestamp: String,
}

impl ChatServer {
    pub fn new(chat_manager: Arc<ChatManager>, port: u16) -> Self {
        Self { chat_manager, port }
    }

    /// Start the web server. This blocks until the server is shut down.
    pub async fn start(&self) -> Result<()> {
        let state = AppState {
            chat_manager: self.chat_manager.clone(),
        };

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/chat/{event_id}", get(chat_page_handler))
            .route("/chat/{event_id}/message", post(send_message_handler))
            .route("/chat/{event_id}/session", get(session_info_handler))
            .with_state(state);

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));
        tracing::info!("Chat server listening on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }

    /// Build the router (useful for testing without binding to a port).
    pub fn router(chat_manager: Arc<ChatManager>) -> Router {
        let state = AppState { chat_manager };
        Router::new()
            .route("/health", get(health_handler))
            .route("/chat/{event_id}", get(chat_page_handler))
            .route("/chat/{event_id}/message", post(send_message_handler))
            .route("/chat/{event_id}/session", get(session_info_handler))
            .with_state(state)
    }
}

async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

async fn session_info_handler(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
) -> impl IntoResponse {
    let session_id = match state.chat_manager.find_session_by_event(&event_id) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "No session found for this event"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
                .into_response();
        }
    };

    match state.chat_manager.get_session(&session_id) {
        Ok(session) => {
            let info = SessionInfo {
                session_id: session.id,
                event_id: session.event_id,
                event_summary: session.event_summary,
                swarm_verdict: session.swarm_verdict,
                messages: session
                    .messages
                    .into_iter()
                    .map(|m| MessageInfo {
                        role: m.role,
                        content: m.content,
                        timestamp: m.timestamp,
                    })
                    .collect(),
            };
            Json(info).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

async fn send_message_handler(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
    Json(body): Json<SendMessageRequest>,
) -> impl IntoResponse {
    // Find or create a session for this event
    let session_id = match state.chat_manager.find_session_by_event(&event_id) {
        Ok(Some(id)) => id,
        Ok(None) => {
            // Auto-create a minimal session
            match state.chat_manager.start_session(
                &event_id,
                &format!("Event {}", event_id),
                "Unknown",
                "No specialist reports available.",
            ) {
                Ok(id) => id,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to create session: {e}"),
                        }),
                    )
                        .into_response();
                }
            }
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("{e}"),
                }),
            )
                .into_response();
        }
    };

    match state
        .chat_manager
        .send_message(&session_id, &body.message)
        .await
    {
        Ok(content) => Json(SendMessageResponse { content }).into_response(),
        Err(e) => {
            let msg = format!("{e}");
            let status = if msg.contains("limit reached") || msg.contains("Budget exceeded") {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(ErrorResponse { error: msg })).into_response()
        }
    }
}

async fn chat_page_handler(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
) -> impl IntoResponse {
    // Load session info if it exists
    let (event_summary, swarm_verdict) = match state.chat_manager.find_session_by_event(&event_id) {
        Ok(Some(session_id)) => match state.chat_manager.get_session(&session_id) {
            Ok(s) => (s.event_summary, s.swarm_verdict),
            Err(_) => (format!("Event {}", event_id), "Unknown".to_string()),
        },
        _ => (format!("Event {}", event_id), "Unknown".to_string()),
    };

    let html = render_chat_page(&event_id, &event_summary, &swarm_verdict);
    Html(html)
}

fn render_chat_page(event_id: &str, event_summary: &str, swarm_verdict: &str) -> String {
    // Escape strings for safe embedding in HTML/JS
    let event_id_escaped = html_escape(event_id);
    let summary_escaped = html_escape(event_summary);
    let verdict_escaped = html_escape(swarm_verdict);

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ClawDefender - Event Chat</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            background: #0d1117;
            color: #c9d1d9;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }}
        .header {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 16px 24px;
        }}
        .header h1 {{
            font-size: 16px;
            color: #58a6ff;
            margin-bottom: 8px;
        }}
        .event-info {{
            background: #1c2128;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            margin-top: 8px;
        }}
        .event-info .label {{
            color: #8b949e;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .event-info .value {{
            color: #c9d1d9;
            font-size: 14px;
            margin-bottom: 8px;
        }}
        .verdict {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
        .verdict.critical {{ background: #f8514930; color: #f85149; border: 1px solid #f8514950; }}
        .verdict.high {{ background: #d2992230; color: #d29922; border: 1px solid #d2992250; }}
        .verdict.medium {{ background: #58a6ff30; color: #58a6ff; border: 1px solid #58a6ff50; }}
        .verdict.low {{ background: #3fb95030; color: #3fb950; border: 1px solid #3fb95050; }}
        .messages {{
            flex: 1;
            overflow-y: auto;
            padding: 16px 24px;
        }}
        .message {{
            margin-bottom: 16px;
            max-width: 80%;
        }}
        .message.user {{
            margin-left: auto;
        }}
        .message .bubble {{
            padding: 10px 14px;
            border-radius: 12px;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre-wrap;
        }}
        .message.user .bubble {{
            background: #1f6feb;
            color: #fff;
            border-bottom-right-radius: 4px;
        }}
        .message.assistant .bubble {{
            background: #21262d;
            border: 1px solid #30363d;
            border-bottom-left-radius: 4px;
        }}
        .message .meta {{
            font-size: 11px;
            color: #484f58;
            margin-top: 4px;
            padding: 0 4px;
        }}
        .message.user .meta {{
            text-align: right;
        }}
        .input-area {{
            background: #161b22;
            border-top: 1px solid #30363d;
            padding: 16px 24px;
            display: flex;
            gap: 12px;
        }}
        .input-area input {{
            flex: 1;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 10px 14px;
            color: #c9d1d9;
            font-size: 14px;
            outline: none;
        }}
        .input-area input:focus {{
            border-color: #58a6ff;
        }}
        .input-area input:disabled {{
            opacity: 0.5;
        }}
        .input-area button {{
            background: #238636;
            color: #fff;
            border: none;
            border-radius: 8px;
            padding: 10px 20px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 500;
        }}
        .input-area button:hover {{
            background: #2ea043;
        }}
        .input-area button:disabled {{
            background: #21262d;
            color: #484f58;
            cursor: not-allowed;
        }}
        .typing {{
            color: #8b949e;
            font-style: italic;
            padding: 8px 14px;
        }}
        .error-msg {{
            background: #f8514920;
            border: 1px solid #f85149;
            color: #f85149;
            border-radius: 8px;
            padding: 10px 14px;
            margin: 8px 24px;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ClawDefender Chat</h1>
        <div class="event-info">
            <div class="label">Event</div>
            <div class="value" id="event-summary">{summary_escaped}</div>
            <div class="label">Swarm Verdict</div>
            <div class="value"><span class="verdict" id="verdict-badge">{verdict_escaped}</span></div>
        </div>
    </div>
    <div class="messages" id="messages"></div>
    <div class="input-area">
        <input type="text" id="user-input" placeholder="Ask about this event..." autofocus>
        <button id="send-btn" onclick="sendMessage()">Send</button>
    </div>

    <script>
        const eventId = '{event_id_escaped}';
        const messagesDiv = document.getElementById('messages');
        const userInput = document.getElementById('user-input');
        const sendBtn = document.getElementById('send-btn');

        // Set verdict badge color
        (function() {{
            const badge = document.getElementById('verdict-badge');
            const text = badge.textContent.toLowerCase();
            if (text.includes('critical')) badge.className = 'verdict critical';
            else if (text.includes('high')) badge.className = 'verdict high';
            else if (text.includes('medium')) badge.className = 'verdict medium';
            else badge.className = 'verdict low';
        }})();

        // Load existing messages
        (async function() {{
            try {{
                const resp = await fetch('/chat/' + eventId + '/session');
                if (resp.ok) {{
                    const data = await resp.json();
                    for (const msg of data.messages) {{
                        appendMessage(msg.role, msg.content, msg.timestamp);
                    }}
                }}
            }} catch(e) {{
                // Session may not exist yet
            }}
        }})();

        userInput.addEventListener('keydown', function(e) {{
            if (e.key === 'Enter' && !e.shiftKey) {{
                e.preventDefault();
                sendMessage();
            }}
        }});

        async function sendMessage() {{
            const message = userInput.value.trim();
            if (!message) return;

            userInput.value = '';
            userInput.disabled = true;
            sendBtn.disabled = true;

            appendMessage('user', message);

            const typingEl = document.createElement('div');
            typingEl.className = 'typing';
            typingEl.textContent = 'Analyzing...';
            messagesDiv.appendChild(typingEl);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;

            try {{
                const resp = await fetch('/chat/' + eventId + '/message', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ message: message }})
                }});

                messagesDiv.removeChild(typingEl);

                if (resp.ok) {{
                    const data = await resp.json();
                    appendMessage('assistant', data.content);
                }} else {{
                    const err = await resp.json();
                    showError(err.error || 'Request failed');
                }}
            }} catch(e) {{
                messagesDiv.removeChild(typingEl);
                showError('Network error: ' + e.message);
            }}

            userInput.disabled = false;
            sendBtn.disabled = false;
            userInput.focus();
        }}

        function appendMessage(role, content, timestamp) {{
            const div = document.createElement('div');
            div.className = 'message ' + role;

            const bubble = document.createElement('div');
            bubble.className = 'bubble';
            bubble.textContent = content;
            div.appendChild(bubble);

            if (timestamp) {{
                const meta = document.createElement('div');
                meta.className = 'meta';
                meta.textContent = timestamp;
                div.appendChild(meta);
            }}

            messagesDiv.appendChild(div);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }}

        function showError(msg) {{
            const div = document.createElement('div');
            div.className = 'error-msg';
            div.textContent = msg;
            messagesDiv.appendChild(div);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }}
    </script>
</body>
</html>"##
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::ChatManager;
    use crate::llm_client::{LlmResponse, MockLlmClient};
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn setup_test_app() -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_server.db");

        let mock = Arc::new(MockLlmClient::new());
        mock.add_response(
            "claude-sonnet-4-20250514",
            LlmResponse {
                content: "Test response from the assistant.".to_string(),
                input_tokens: 100,
                output_tokens: 20,
                model: "claude-sonnet-4-20250514".to_string(),
                latency_ms: 50,
            },
        );

        let manager = Arc::new(ChatManager::new(&db_path, mock, None).unwrap());
        let router = ChatServer::router(manager);
        (router, dir)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (app, _dir) = setup_test_app();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_chat_page_serves_html() {
        let (app, _dir) = setup_test_app();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/chat/evt-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("ClawDefender Chat"));
        assert!(html.contains("evt-001"));
    }

    #[tokio::test]
    async fn test_send_message_creates_session() {
        let (app, _dir) = setup_test_app();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/chat/evt-new/message")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"message":"What happened?"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["content"].as_str().unwrap().len() > 0);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"hello\""), "&quot;hello&quot;");
    }
}
