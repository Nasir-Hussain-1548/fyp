//! Hybrid Storage Engine for Percepta SIEM
//!
//! This module implements a high-performance, durable storage mechanism using
//! an in-memory cache fronted by a Write-Ahead Log (WAL).
//!
//! - **Ingestion**: Events are simultaneously written to the WAL for durability
//!   and pushed to a bounded in-memory cache for real-time access.
//! - **GUI Reads**: The web interface reads from the in-memory cache for maximum speed.
//! - **Durability**: The WAL ensures that events are not lost if the server crashes.
//!   On restart, the server will replay the WAL to rebuild its in-memory state.
//! - **Compaction**: Periodically, the WAL is compacted into a persistent SQLite
//!   database to prevent infinite growth and provide long-term storage.

use anyhow::{Context, Result};
use percepta_server::percepta::Event;
use rusqlite::Connection;
use serde_json;
use std::collections::VecDeque;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const MAX_IN_MEMORY_EVENTS: usize = 10_000; // Keep the most recent 10k events in RAM
const WAL_FILE_NAME: &str = "events.wal";
const DB_FILE_NAME: &str = "percepta.db";

/// The central storage service for the SIEM.
#[derive(Debug)]
pub struct StorageService {
    in_memory_cache: Arc<Mutex<VecDeque<Event>>>,
    wal_file: Arc<Mutex<File>>,
    storage_path: PathBuf,
    db_path: PathBuf, // Store the path instead of the connection
}

#[cfg(test)]
mod tests {
    use super::*;
    use percepta_server::percepta::Event;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_store_and_retrieve_event() {
        let dir = tempdir().unwrap();
        let storage = StorageService::new(dir.path()).await.expect("storage init");

        // Build a minimal event
        let mut event = Event::default();
        event.hash = Uuid::new_v4().to_string();

        // Store event
        storage
            .store_event(&event)
            .await
            .expect("store_event failed");

        // Retrieve recent events
        let recent = storage.get_recent_events().await;
        assert!(!recent.is_empty(), "Recent events should not be empty");
        assert_eq!(recent[0].hash, event.hash);
    }
}

impl StorageService {
    /// Creates a new instance of the StorageService.
    pub async fn new(storage_path: impl AsRef<Path>) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();
        fs::create_dir_all(&storage_path)
            .await
            .context("Failed to create storage directory")?;

        // --- Initialize SQLite database and table ---
        let db_path = storage_path.join(DB_FILE_NAME);
        let conn = Connection::open(&db_path).context(format!(
            "Failed to open SQLite database at {}",
            db_path.display()
        ))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                hash TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                content TEXT NOT NULL
            )",
            [],
        )
        .context("Failed to create events table in SQLite")?;
        info!("🗃️ SQLite database initialized at {}", db_path.display());
        // Connection is dropped here, which is fine. We'll open new ones in blocking tasks.

        // --- Initialize WAL ---
        let wal_path = storage_path.join(WAL_FILE_NAME);
        let in_memory_cache = Arc::new(Mutex::new(Self::replay_wal(&wal_path).await?));
        info!(
            "Recovered {} events from WAL",
            in_memory_cache.lock().await.len()
        );

        let wal_file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .await
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                // Attempt to relax file permissions and retry. If that fails, rotate the file.
                if wal_path.exists() {
                    #[cfg(unix)]
                    {
                        let _ =
                            fs::set_permissions(&wal_path, std::fs::Permissions::from_mode(0o644))
                                .await;
                    }
                    match OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&wal_path)
                        .await
                    {
                        Ok(f) => f,
                        Err(_) => {
                            let backup = wal_path.with_extension("wal.readonly.bak");
                            let _ = fs::rename(&wal_path, &backup).await;
                            OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&wal_path)
                                .await
                                .context("Failed to open Write-Ahead Log file after adjusting permissions/rotation")?
                        }
                    }
                } else {
                    return Err(e).context("Failed to open Write-Ahead Log file")?;
                }
            }
            Err(e) => return Err(e).context("Failed to open Write-Ahead Log file")?,
        };

        info!(
            "🗄️ Hybrid Storage Engine initialized. Path: {}",
            storage_path.display()
        );

        Ok(Self {
            in_memory_cache,
            wal_file: Arc::new(Mutex::new(wal_file)),
            storage_path,
            db_path, // Store the path
        })
    }

    /// Stores a single event.
    pub async fn store_event(&self, event: &Event) -> Result<()> {
        let event_json = serde_json::to_string(event)?;

        {
            let mut file = self.wal_file.lock().await;
            file.write_all(event_json.as_bytes()).await?;
            file.write_all(b"\n").await?;
            file.flush().await.context("Failed to flush WAL")?;
        }

        {
            let mut cache = self.in_memory_cache.lock().await;
            cache.push_front(event.clone());
            if cache.len() > MAX_IN_MEMORY_EVENTS {
                cache.pop_back();
            }
        }

        debug!("Stored event {} in WAL and in-memory cache.", event.hash);
        Ok(())
    }

    /// Returns a clone of the most recent events from the in-memory cache.
    pub async fn get_recent_events(&self) -> Vec<Event> {
        self.in_memory_cache
            .lock()
            .await
            .clone()
            .into_iter()
            .collect()
    }

    /// Replays the WAL file to rebuild the in-memory cache on startup.
    async fn replay_wal(wal_path: &Path) -> Result<VecDeque<Event>> {
        if !wal_path.exists() {
            return Ok(VecDeque::new());
        }

        let file = File::open(wal_path).await?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut cache = VecDeque::with_capacity(MAX_IN_MEMORY_EVENTS);

        while reader.read_line(&mut line).await? > 0 {
            if let Ok(event) = serde_json::from_str::<Event>(&line) {
                cache.push_front(event);
                if cache.len() > MAX_IN_MEMORY_EVENTS {
                    cache.pop_back();
                }
            } else {
                warn!("Failed to parse line in WAL during replay: {}", line.trim());
            }
            line.clear();
        }

        Ok(cache)
    }

    /// Compacts the current WAL file into the persistent SQLite database.
    pub async fn compact_wal(&self) -> Result<()> {
        info!("🔄 Starting WAL compaction process...");
        let wal_path = self.storage_path.join(WAL_FILE_NAME);
        let compacting_path = self.storage_path.join("events.wal.compacting");

        // 1. Rotate WAL file
        {
            let mut wal_file_guard = self.wal_file.lock().await;

            if wal_file_guard.metadata().await?.len() == 0 {
                info!("WAL file is empty, skipping compaction.");
                return Ok(());
            }

            wal_file_guard.flush().await?;
            drop(wal_file_guard);

            fs::rename(&wal_path, &compacting_path)
                .await
                .context("Failed to rename WAL for compaction")?;

            let new_wal_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&wal_path)
                .await
                .context("Failed to create new WAL file after rotation")?;

            *self.wal_file.lock().await = new_wal_file;
        }
        info!("Rotated WAL file. New events will go to the new file.");

        // 2. Process the rotated WAL file
        let mut events_to_insert = Vec::new();
        let file = File::open(&compacting_path).await?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();

        while reader.read_line(&mut line).await? > 0 {
            if let Ok(event) = serde_json::from_str::<Event>(&line) {
                let timestamp = event.event_time.as_ref().map_or(0, |t| t.seconds);
                let content = serde_json::to_string(&event)?;
                events_to_insert.push((event.hash.clone(), timestamp, content));
            } else {
                warn!("Failed to parse line in compacting WAL: {}", line.trim());
            }
            line.clear();
        }

        // 3. Batch insert into SQLite in a blocking task
        let db_path = self.db_path.clone();
        let insert_count = events_to_insert.len();

        if insert_count > 0 {
            tokio::task::spawn_blocking(move || -> Result<()> {
                let mut conn = Connection::open(db_path)?;
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare("INSERT OR IGNORE INTO events (hash, timestamp, content) VALUES (?1, ?2, ?3)")?;
                    for (hash, timestamp, content) in events_to_insert {
                        stmt.execute((&hash, &timestamp, &content))?;
                    }
                }
                tx.commit()?;
                Ok(())
            }).await??;
            info!("💾 Compacted {} events from WAL into SQLite.", insert_count);
        }

        // 4. Clean up the compacted WAL file
        fs::remove_file(&compacting_path)
            .await
            .context("Failed to remove compacted WAL file")?;
        info!("✅ WAL compaction process finished successfully.");

        Ok(())
    }
}
