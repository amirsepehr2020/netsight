use crate::session::{SessionStore, SessionSummary};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_db() -> std::path::PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("netsight-session-{stamp}.db"))
}

#[test]
fn session_lifecycle_persists_and_lists() {
    let path = temp_db();
    let store = SessionStore::open(&path).unwrap();
    let id = store.start("Wi-Fi").unwrap();
    store.append_snapshot(&id, "{\"packets\":42}").unwrap();
    store.finish(&id).unwrap();

    let reopened = SessionStore::open(&path).unwrap();
    let sessions = reopened.list().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, id);
    assert_eq!(sessions[0].capture_device, "Wi-Fi");
    assert_eq!(sessions[0].state, "finished");
    assert_eq!(reopened.load_latest_snapshot(&id).unwrap().as_deref(), Some("{\"packets\":42}"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn interrupted_session_is_recovered_as_interrupted() {
    let path = temp_db();
    {
        let store = SessionStore::open(&path).unwrap();
        let _ = store.start("Ethernet").unwrap();
    }

    let reopened = SessionStore::open(&path).unwrap();
    let sessions: Vec<SessionSummary> = reopened.list().unwrap();
    assert_eq!(sessions[0].state, "interrupted");

    let _ = std::fs::remove_file(path);
}
