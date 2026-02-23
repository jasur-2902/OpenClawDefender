//! Integration test to diagnose download failures.
//!
//! This test exercises the DownloadManager against a real HuggingFace URL
//! to verify that HTTPS connections succeed and progress is reported.

use clawdefender_slm::downloader::DownloadManager;

#[tokio::test]
async fn test_download_starts_and_progresses() {
    let tmp = std::env::temp_dir().join("clawdefender-download-test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let mgr = DownloadManager::new();

    // Use gemma3-1b which is the smallest model (~800MB) and has a known-good URL
    let result = mgr.start_download("gemma3-1b-q4", &tmp).await;
    match &result {
        Ok(task_id) => {
            println!("Download started with task_id: {}", task_id);
            // Poll progress for up to 10 seconds
            for i in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Some(prog) = mgr.get_progress(task_id).await {
                    println!(
                        "Poll {}: status={:?} downloaded={} total={} percent={:.1}%",
                        i, prog.status, prog.bytes_downloaded, prog.bytes_total, prog.percent
                    );
                    match &prog.status {
                        clawdefender_slm::downloader::DownloadStatus::Failed(err) => {
                            println!("DOWNLOAD FAILED with error: {}", err);
                            // This is likely the TLS root cert issue
                            assert!(
                                false,
                                "Download failed (likely TLS root cert issue): {}",
                                err
                            );
                        }
                        _ => {}
                    }
                    if prog.bytes_downloaded > 0 {
                        println!("SUCCESS: Download is progressing! Downloaded {} bytes", prog.bytes_downloaded);
                        // Cancel since we don't want to download the full model
                        let cancelled = mgr.cancel(task_id).await;
                        println!("Cancel result: {}", cancelled);
                        assert!(cancelled, "cancel should return true for active download");
                        // Give it a moment to process cancellation
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        if let Some(final_prog) = mgr.get_progress(task_id).await {
                            println!("Final status after cancel: {:?}", final_prog.status);
                        }
                        break;
                    }
                } else {
                    println!("Poll {}: no progress found for task_id", i);
                }
            }
        }
        Err(e) => {
            println!("Download FAILED to start: {}", e);
            assert!(false, "start_download failed: {}", e);
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn test_cancel_stops_download() {
    let tmp = std::env::temp_dir().join("clawdefender-cancel-test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let mgr = DownloadManager::new();

    let result = mgr.start_download("gemma3-1b-q4", &tmp).await;
    match result {
        Ok(task_id) => {
            // Immediately cancel
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let cancelled = mgr.cancel(&task_id).await;
            println!("Immediate cancel result: {}", cancelled);

            // Wait and check final status
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Some(prog) = mgr.get_progress(&task_id).await {
                println!("Status after cancel: {:?}", prog.status);
                // Should be either Cancelled or Failed, not still Downloading
                assert!(
                    matches!(
                        prog.status,
                        clawdefender_slm::downloader::DownloadStatus::Cancelled
                            | clawdefender_slm::downloader::DownloadStatus::Failed(_)
                    ),
                    "Expected Cancelled or Failed, got {:?}",
                    prog.status
                );
            }
        }
        Err(e) => {
            println!("start_download failed (expected if TLS broken): {}", e);
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Test that reqwest can actually make an HTTPS request.
/// This isolates whether the TLS root certificate issue exists.
#[tokio::test]
async fn test_reqwest_https_connectivity() {
    println!("Testing basic HTTPS connectivity with reqwest...");

    // Build a client the same way DownloadManager does (no special TLS config)
    let client = reqwest::Client::builder()
        .user_agent("ClawDefender-Test/0.1")
        .connect_timeout(std::time::Duration::from_secs(10))
        .build();

    match client {
        Ok(client) => {
            println!("Client built successfully");
            // Try a simple HEAD request to HuggingFace
            let result = client
                .head("https://huggingface.co/ggml-org/gemma-3-1b-it-GGUF/resolve/main/gemma-3-1b-it-Q4_K_M.gguf")
                .send()
                .await;

            match result {
                Ok(resp) => {
                    println!("HTTPS request succeeded! Status: {}", resp.status());
                    println!("This means TLS root certificates ARE available.");
                }
                Err(e) => {
                    println!("HTTPS request FAILED: {}", e);
                    if format!("{:?}", e).contains("certificate") || format!("{:?}", e).contains("tls") || format!("{:?}", e).contains("ssl") {
                        println!("ROOT CAUSE CONFIRMED: TLS certificate verification failed.");
                        println!("Fix: Add 'rustls-tls-native-roots' to reqwest features in Cargo.toml");
                    }
                    assert!(false, "HTTPS request failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to build reqwest client: {}", e);
            assert!(false, "Client build failed: {}", e);
        }
    }
}
