use orangespace_core::{NodeId, SandboxId, UserId};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sandbox not found for this user")]
    NotFound,
    #[error("sandbox has no node binding")]
    Unbound,
    #[error("invalid sandbox name (1–80 visible characters required)")]
    InvalidName,
    #[error("generation space exhausted")]
    Exhausted,
    #[error("local data path must contain real directories, not symbolic links")]
    UnsafePath,
    #[error("local storage operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("local database operation failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("invalid local metadata")]
    InvalidMetadata,
}

#[derive(Debug, Serialize)]
pub struct SandboxRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub node_id: Option<Uuid>,
    pub generation: u64,
    pub state: String,
    pub profile_path: String,
}

#[derive(Debug, Serialize)]
pub struct TaskRecord {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub node_id: Uuid,
    pub state: String,
}

pub struct Store {
    db: Connection,
    root: PathBuf,
}

fn real_directory(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(StoreError::UnsafePath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

impl Store {
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        // Create only the explicitly selected base; generated descendants are
        // checked separately. The desktop OS account owns this local state.
        if !root.exists() {
            fs::create_dir_all(root)?;
        }
        real_directory(root)?;
        let root = fs::canonicalize(root)?;
        real_directory(&root.join("users"))?;
        let db_path = root.join("state.sqlite3");
        match fs::symlink_metadata(&db_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(StoreError::UnsafePath);
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options.open(&db_path)?;
            }
            Err(error) => return Err(error.into()),
        }
        let db = Connection::open(db_path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS sandboxes (
              id TEXT PRIMARY KEY NOT NULL,
              user_id TEXT NOT NULL,
              name TEXT NOT NULL,
              node_id TEXT,
              generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
              state TEXT NOT NULL DEFAULT 'closed' CHECK(state IN ('closed','blocked','deleting'))
            );
            CREATE INDEX IF NOT EXISTS sandboxes_user ON sandboxes(user_id);
            CREATE TABLE IF NOT EXISTS transfers (
              id TEXT PRIMARY KEY NOT NULL,
              user_id TEXT NOT NULL,
              sandbox_id TEXT NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
              node_id TEXT NOT NULL,
              state TEXT NOT NULL DEFAULT 'pending'
            );",
        )?;
        Ok(Self { db, root })
    }

    fn sandbox_path(&self, user: UserId, sandbox: SandboxId) -> PathBuf {
        self.root
            .join("users")
            .join(user.to_string())
            .join("sandboxes")
            .join(sandbox.to_string())
    }

    fn ensure_sandbox_path(&self, user: UserId, sandbox: SandboxId) -> Result<PathBuf, StoreError> {
        let user_path = self.root.join("users").join(user.to_string());
        real_directory(&user_path)?;
        real_directory(&user_path.join("sandboxes"))?;
        let path = self.sandbox_path(user, sandbox);
        real_directory(&path)?;
        for name in ["profile", "cache", "tasks"] {
            real_directory(&path.join(name))?;
        }
        Ok(path)
    }

    fn decode(
        &self,
        tuple: (String, String, String, Option<String>, i64, String),
    ) -> Result<SandboxRecord, StoreError> {
        let (id, user, name, node, generation, state) = tuple;
        let id = Uuid::parse_str(&id).map_err(|_| StoreError::InvalidMetadata)?;
        let user_id = Uuid::parse_str(&user).map_err(|_| StoreError::InvalidMetadata)?;
        Ok(SandboxRecord {
            id,
            user_id,
            name,
            node_id: node
                .map(|v| Uuid::parse_str(&v))
                .transpose()
                .map_err(|_| StoreError::InvalidMetadata)?,
            generation: u64::try_from(generation).map_err(|_| StoreError::InvalidMetadata)?,
            state,
            profile_path: self
                .sandbox_path(UserId(user_id), SandboxId(id))
                .join("profile")
                .to_string_lossy()
                .into_owned(),
        })
    }

    pub fn list(&self, user: Option<UserId>) -> Result<Vec<SandboxRecord>, StoreError> {
        let mut stmt = self.db.prepare(
            "SELECT id,user_id,name,node_id,generation,state FROM sandboxes
            WHERE (?1 IS NULL OR user_id=?1) ORDER BY name,id",
        )?;
        let rows = stmt.query_map([user.map(|u| u.to_string())], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?;
        rows.map(|row| self.decode(row?)).collect()
    }

    pub fn get(&self, user: UserId, sandbox: SandboxId) -> Result<SandboxRecord, StoreError> {
        let tuple = self.db.query_row("SELECT id,user_id,name,node_id,generation,state FROM sandboxes WHERE id=?1 AND user_id=?2",
            params![sandbox.to_string(), user.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).optional()?.ok_or(StoreError::NotFound)?;
        self.decode(tuple)
    }

    pub fn create(&self, user: UserId, name: &str) -> Result<SandboxRecord, StoreError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
            return Err(StoreError::InvalidName);
        }
        let sandbox = SandboxId::new();
        let path = self.ensure_sandbox_path(user, sandbox)?;
        if let Err(error) = self.db.execute(
            "INSERT INTO sandboxes(id,user_id,name) VALUES (?1,?2,?3)",
            params![sandbox.to_string(), user.to_string(), name],
        ) {
            let _ = fs::remove_dir_all(path);
            return Err(error.into());
        }
        self.get(user, sandbox)
    }

    pub fn bind(
        &self,
        user: UserId,
        sandbox: SandboxId,
        node: NodeId,
    ) -> Result<SandboxRecord, StoreError> {
        // SQL arithmetic is atomic even when two manager processes bind at once.
        self.get(user, sandbox)?;
        let changed = self.db.execute(
            "UPDATE sandboxes SET node_id=?1,generation=generation+1,state='blocked'
            WHERE id=?2 AND user_id=?3 AND state<>'deleting' AND generation<9223372036854775807",
            params![node.to_string(), sandbox.to_string(), user.to_string()],
        )?;
        if changed == 0 {
            return Err(StoreError::Exhausted);
        }
        self.get(user, sandbox)
    }

    pub fn close(&self, user: UserId, sandbox: SandboxId) -> Result<SandboxRecord, StoreError> {
        self.get(user, sandbox)?;
        self.db.execute(
            "UPDATE sandboxes SET state='closed' WHERE id=?1 AND user_id=?2 AND state<>'deleting'",
            params![sandbox.to_string(), user.to_string()],
        )?;
        self.get(user, sandbox)
    }

    pub fn delete(&self, user: UserId, sandbox: SandboxId) -> Result<(), StoreError> {
        self.get(user, sandbox)?;
        self.db.execute(
            "UPDATE sandboxes SET state='deleting' WHERE id=?1 AND user_id=?2",
            params![sandbox.to_string(), user.to_string()],
        )?;
        let user_path = self.root.join("users").join(user.to_string());
        // Validate each generated ancestor before recursive deletion. This is
        // local-account storage, not a defense against that OS account replacing
        // paths concurrently; production requires per-sandbox Windows ACLs.
        real_directory(&user_path)?;
        real_directory(&user_path.join("sandboxes"))?;
        let path = self.sandbox_path(user, sandbox);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => fs::remove_dir_all(path)?,
            Ok(_) => return Err(StoreError::UnsafePath),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        self.db.execute(
            "DELETE FROM sandboxes WHERE id=?1 AND user_id=?2",
            params![sandbox.to_string(), user.to_string()],
        )?;
        // Deliberately no network request: shared Linux personal files survive.
        Ok(())
    }

    pub fn create_task(&self, user: UserId, sandbox: SandboxId) -> Result<TaskRecord, StoreError> {
        let record = self.get(user, sandbox)?;
        let node = record.node_id.ok_or(StoreError::Unbound)?;
        if record.state == "deleting" {
            return Err(StoreError::NotFound);
        }
        let task = TaskRecord {
            id: Uuid::new_v4(),
            sandbox_id: sandbox.0,
            node_id: node,
            state: "pending".into(),
        };
        self.db.execute(
            "INSERT INTO transfers(id,user_id,sandbox_id,node_id,state) VALUES (?1,?2,?3,?4,?5)",
            params![
                task.id.to_string(),
                user.to_string(),
                sandbox.to_string(),
                node.to_string(),
                task.state
            ],
        )?;
        Ok(task)
    }

    pub fn list_tasks(
        &self,
        user: UserId,
        sandbox: SandboxId,
    ) -> Result<Vec<TaskRecord>, StoreError> {
        self.get(user, sandbox)?;
        let mut stmt = self.db.prepare(
            "SELECT id,node_id,state FROM transfers WHERE user_id=?1 AND sandbox_id=?2 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![user.to_string(), sandbox.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (id, node, state) = row?;
            Ok(TaskRecord {
                id: Uuid::parse_str(&id).map_err(|_| StoreError::InvalidMetadata)?,
                sandbox_id: sandbox.0,
                node_id: Uuid::parse_str(&node).map_err(|_| StoreError::InvalidMetadata)?,
                state,
            })
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn switch_and_close_keep_profile_delete_removes_only_selected_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let user = UserId::new();
        let a = store.create(user, "深圳工作区").unwrap();
        let b = store.create(user, "广州工作区").unwrap();
        let cookie = Path::new(&a.profile_path).join("Cookies");
        fs::write(&cookie, "test-cookie").unwrap();
        let old_node = NodeId::new();
        store.bind(user, SandboxId(a.id), old_node).unwrap();
        let task = store.create_task(user, SandboxId(a.id)).unwrap();
        store.bind(user, SandboxId(a.id), NodeId::new()).unwrap();
        store.close(user, SandboxId(a.id)).unwrap();
        assert!(cookie.exists());
        assert_eq!(
            store.list_tasks(user, SandboxId(a.id)).unwrap()[0].node_id,
            old_node.0
        );
        assert_eq!(task.node_id, old_node.0);
        store.delete(user, SandboxId(a.id)).unwrap();
        assert!(!cookie.exists());
        assert!(Path::new(&b.profile_path).exists());
        assert!(store.get(user, SandboxId(a.id)).is_err());
    }

    #[test]
    fn ownership_and_persisted_generation_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let user = UserId::new();
        let sandbox = {
            let store = Store::open(dir.path()).unwrap();
            let record = store.create(user, "test").unwrap();
            let sandbox = SandboxId(record.id);
            store.bind(user, sandbox, NodeId::new()).unwrap();
            assert!(matches!(
                store.delete(UserId::new(), sandbox),
                Err(StoreError::NotFound)
            ));
            sandbox
        };
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(
            store.bind(user, sandbox, NodeId::new()).unwrap().generation,
            2
        );
        assert!(store.list(Some(UserId::new())).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn deletion_refuses_a_replaced_sandbox_root_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let user = UserId::new();
        let record = store.create(user, "test").unwrap();
        let root = Path::new(&record.profile_path).parent().unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::write(outside.path().join("keep.txt"), "keep").unwrap();
        symlink(outside.path(), root).unwrap();
        assert!(matches!(
            store.delete(user, SandboxId(record.id)),
            Err(StoreError::UnsafePath)
        ));
        assert!(outside.path().join("keep.txt").exists());
        assert_eq!(
            store.get(user, SandboxId(record.id)).unwrap().state,
            "deleting"
        );
    }
}
