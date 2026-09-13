use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: String,
    pub capture_device: String,
    pub state: String,
    pub started_at_ms: i64,
    pub finished_at_ms: Option<i64>,
    pub snapshot_count: u64,
}

#[derive(Debug)]
pub struct SessionStore {
    connection: Connection,
}

impl SessionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).with_context(|| "open NetSight session database")?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS sessions (
                 id TEXT PRIMARY KEY,
                 capture_device TEXT NOT NULL,
                 state TEXT NOT NULL,
                 started_at_ms INTEGER NOT NULL,
                 finished_at_ms INTEGER
             );
             CREATE TABLE IF NOT EXISTS session_snapshots (
                 session_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL,
                 captured_at_ms INTEGER NOT NULL,
                 payload TEXT NOT NULL,
                 PRIMARY KEY (session_id, sequence),
                 FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at_ms DESC);
             CREATE INDEX IF NOT EXISTS idx_snapshots_session ON session_snapshots(session_id, sequence DESC);",
        )?;
        // A process that crashed while capturing leaves its last session running.
        // On next startup it is explicitly marked interrupted for recovery/history UI.
        connection.execute(
            "UPDATE sessions SET state='interrupted' WHERE state='running'",
            [],
        )?;
        Ok(Self { connection })
    }

    pub fn start(&self, capture_device: impl AsRef<str>) -> Result<String> {
        let now = now_ms();
        let id = format!("session-{now}-{}", SESSION_COUNTER.fetch_add(1, Ordering::Relaxed));
        self.connection.execute(
            "INSERT INTO sessions (id, capture_device, state, started_at_ms) VALUES (?1, ?2, 'running', ?3)",
            params![id, capture_device.as_ref(), now],
        )?;
        Ok(id)
    }

    pub fn append_snapshot(&self, session_id: &str, payload: &str) -> Result<()> {
        let next: i64 = self.connection.query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM session_snapshots WHERE session_id=?1",
            params![session_id],
            |row| row.get(0),
        )?;
        self.connection.execute(
            "INSERT INTO session_snapshots (session_id, sequence, captured_at_ms, payload) VALUES (?1, ?2, ?3, ?4)",
            params![session_id, next, now_ms(), payload],
        )?;
        Ok(())
    }

    pub fn finish(&self, session_id: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE sessions SET state='finished', finished_at_ms=?1 WHERE id=?2 AND state='running'",
            params![now_ms(), session_id],
        )?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SessionSummary>> {
        let mut stmt = self.connection.prepare(
            "SELECT s.id, s.capture_device, s.state, s.started_at_ms, s.finished_at_ms,
                    (SELECT COUNT(*) FROM session_snapshots x WHERE x.session_id=s.id)
             FROM sessions s ORDER BY s.started_at_ms DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SessionSummary {
                id: row.get(0)?,
                capture_device: row.get(1)?,
                state: row.get(2)?,
                started_at_ms: row.get(3)?,
                finished_at_ms: row.get(4)?,
                snapshot_count: row.get::<_, i64>(5)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn load_latest_snapshot(&self, session_id: &str) -> Result<Option<String>> {
        Ok(self.connection.query_row(
            "SELECT payload FROM session_snapshots WHERE session_id=?1 ORDER BY sequence DESC LIMIT 1",
            params![session_id],
            |row| row.get(0),
        ).optional()?)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}
