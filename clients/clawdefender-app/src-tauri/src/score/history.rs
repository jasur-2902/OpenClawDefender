use rusqlite::{params, Connection};

use super::calculator::ScoreSnapshot;

/// Path to the score history SQLite database.
fn db_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home)
        .join(".local/share/rookbot/score_history.db")
}

/// Open (or create) the score history database with the schema in place.
fn open_db() -> Result<Connection, rusqlite::Error> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let conn = Connection::open(&path)?;
    // Enable WAL mode for crash safety — prevents database corruption if
    // the process is killed mid-write.
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS score_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            score       INTEGER NOT NULL,
            factors_json TEXT NOT NULL,
            computed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_score_computed_at ON score_snapshots(computed_at);",
    )?;
    Ok(conn)
}

/// Store a score snapshot. Deduplicates: skips if score equals the most recent entry.
pub fn store_snapshot(score: u32, factors_json: &str, computed_at: &str) {
    let conn = match open_db() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to open score history DB: {}", e);
            return;
        }
    };

    // Deduplicate: skip if same score as last
    let last: Option<u32> = conn
        .query_row(
            "SELECT score FROM score_snapshots ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();

    if last == Some(score) {
        return;
    }

    if let Err(e) = conn.execute(
        "INSERT INTO score_snapshots (score, factors_json, computed_at) VALUES (?1, ?2, ?3)",
        params![score, factors_json, computed_at],
    ) {
        tracing::warn!("Failed to insert score snapshot: {}", e);
    }
}

/// Get the most recent score value, if any.
pub fn get_last_score() -> Option<u32> {
    let conn = open_db().ok()?;
    conn.query_row(
        "SELECT score FROM score_snapshots ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    )
    .ok()
}

/// Retrieve score history for the given number of days.
///
/// Returns one snapshot per hour (the most recent per hour) to keep the
/// response size reasonable. Results ordered oldest-first.
pub fn get_score_history(days: u32) -> Vec<ScoreSnapshot> {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
    let cutoff_str = cutoff.to_rfc3339();

    // One snapshot per hour: group by the hour portion of computed_at,
    // take the row with the highest id in each group.
    let mut stmt = match conn.prepare(
        "SELECT id, score, factors_json, computed_at
         FROM score_snapshots
         WHERE computed_at >= ?1
         GROUP BY strftime('%Y-%m-%d %H', computed_at)
         HAVING id = MAX(id)
         ORDER BY computed_at ASC",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let rows = stmt
        .query_map(params![cutoff_str], |row| {
            Ok(ScoreSnapshot {
                id: row.get(0)?,
                score: row.get(1)?,
                factors_json: row.get(2)?,
                computed_at: row.get(3)?,
            })
        })
        .ok();

    match rows {
        Some(iter) => iter.filter_map(|r| r.ok()).collect(),
        None => vec![],
    }
}

/// Remove snapshots older than the retention period (default 90 days).
pub fn vacuum(retention_days: u32) {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return,
    };

    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
    let cutoff_str = cutoff.to_rfc3339();

    let _ = conn.execute(
        "DELETE FROM score_snapshots WHERE computed_at < ?1",
        params![cutoff_str],
    );
}
