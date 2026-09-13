use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::traffic::{FlowKey, FlowStats};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSession {
    pub id: i64,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub status: String,
}

pub struct PersistentStore {
    conn: Connection,
}

impl PersistentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open NetSight SQLite store")?;
        let store = Self { conn };
        store.initialize()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("open in-memory SQLite store")?;
        let store = Self { conn };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS capture_sessions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 started_at_ms INTEGER NOT NULL,
                 ended_at_ms INTEGER,
                 status TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS flows (
                 session_id INTEGER NOT NULL,
                 source_ip TEXT NOT NULL,
                 destination_ip TEXT NOT NULL,
                 protocol TEXT NOT NULL,
                 source_port INTEGER,
                 destination_port INTEGER,
                 packets INTEGER NOT NULL,
                 bytes INTEGER NOT NULL,
                 PRIMARY KEY(session_id, source_ip, destination_ip, protocol, source_port, destination_port),
                 FOREIGN KEY(session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
             CREATE INDEX IF NOT EXISTS idx_sessions_started ON capture_sessions(started_at_ms);",
        )?;
        Ok(())
    }

    pub fn start_session(&mut self, started_at_ms: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO capture_sessions(started_at_ms, status) VALUES (?1, 'running')",
            params![started_at_ms],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_session(&mut self, id: i64, ended_at_ms: i64, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE capture_sessions SET ended_at_ms=?1, status=?2 WHERE id=?3",
            params![ended_at_ms, status, id],
        )?;
        Ok(())
    }

    pub fn recover_open_sessions(&mut self, recovered_at_ms: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE capture_sessions SET ended_at_ms=?1, status='recovered' WHERE status IN ('running','stopping') AND ended_at_ms IS NULL",
            params![recovered_at_ms],
        )?)
    }

    pub fn session(&self, id: i64) -> Result<Option<CaptureSession>> {
        Ok(self.conn.query_row(
            "SELECT id, started_at_ms, ended_at_ms, status FROM capture_sessions WHERE id=?1",
            params![id],
            |row| Ok(CaptureSession {
                id: row.get(0)?, started_at_ms: row.get(1)?, ended_at_ms: row.get(2)?, status: row.get(3)?,
            }),
        ).optional()?)
    }

    pub fn persist_flows<I>(&mut self, session_id: i64, flows: I) -> Result<usize>
    where
        I: IntoIterator<Item = (FlowKey, FlowStats)>,
    {
        let tx = self.conn.transaction()?;
        let count = Self::persist_flows_tx(&tx, session_id, flows)?;
        tx.commit()?;
        Ok(count)
    }

    fn persist_flows_tx<I>(tx: &Transaction<'_>, session_id: i64, flows: I) -> Result<usize>
    where
        I: IntoIterator<Item = (FlowKey, FlowStats)>,
    {
        let mut stmt = tx.prepare(
            "INSERT INTO flows(session_id,source_ip,destination_ip,protocol,source_port,destination_port,packets,bytes)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(session_id,source_ip,destination_ip,protocol,source_port,destination_port)
             DO UPDATE SET packets=excluded.packets, bytes=excluded.bytes",
        )?;
        let mut count = 0;
        for (key, stats) in flows {
            stmt.execute(params![
                session_id, key.source.to_string(), key.destination.to_string(), key.protocol,
                key.source_port, key.destination_port, stats.packets, stats.bytes
            ])?;
            count += 1;
        }
        Ok(count)
    }

    pub fn flow_count(&self, session_id: i64) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM flows WHERE session_id=?1", params![session_id], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn flow() -> (FlowKey, FlowStats) {
        (FlowKey {
            source: "192.168.1.10".parse::<IpAddr>().unwrap(), destination: "1.1.1.1".parse().unwrap(),
            protocol: "TCP".into(), source_port: Some(50000), destination_port: Some(443),
        }, FlowStats { packets: 4, bytes: 4096 })
    }

    #[test]
    fn persists_session_and_flow() -> Result<()> {
        let mut db = PersistentStore::in_memory()?;
        let id = db.start_session(100)?;
        assert_eq!(db.persist_flows(id, [flow()])?, 1);
        assert_eq!(db.flow_count(id)?, 1);
        db.finish_session(id, 200, "stopped")?;
        assert_eq!(db.session(id)?.unwrap().status, "stopped");
        Ok(())
    }

    #[test]
    fn recovers_interrupted_sessions() -> Result<()> {
        let mut db = PersistentStore::in_memory()?;
        let id = db.start_session(100)?;
        assert_eq!(db.recover_open_sessions(200)?, 1);
        assert_eq!(db.session(id)?.unwrap().status, "recovered");
        Ok(())
    }
}
