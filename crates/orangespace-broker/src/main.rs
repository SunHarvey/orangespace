mod store;

use clap::{Parser, Subcommand};
use orangespace_core::{
    Binding, NodeId, SandboxId, TunnelId, UserId,
    guard::{GuardBackend, UnavailableGuard, unavailable},
    tunnel::{TunnelSettings, sing_box_config},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
use store::{Store, StoreError};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    version,
    about = "OrangeSpace local control-plane broker (browser networking remains blocked)"
)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status {
        #[arg(long)]
        user: Option<Uuid>,
    },
    List {
        #[arg(long)]
        user: Uuid,
    },
    Create {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        name: String,
    },
    Bind {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        sandbox: Uuid,
        #[arg(long)]
        node: Uuid,
    },
    Close {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        sandbox: Uuid,
    },
    Delete {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        sandbox: Uuid,
    },
    Open {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        sandbox: Uuid,
    },
    /// Write an OFFLINE configuration artifact. Does not launch sing-box or browsers.
    TunnelConfig {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        sandbox: Uuid,
        #[arg(long)]
        settings_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Record a task's immutable target only; does not transfer bytes yet.
    TaskCreate {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        sandbox: Uuid,
    },
    TaskList {
        #[arg(long)]
        user: Uuid,
        #[arg(long)]
        sandbox: Uuid,
    },
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("provide --data-dir; the default path is available only on Windows")]
    NoDataDirectory,
    #[error("could not read or write configuration artifact")]
    ConfigIo(#[from] io::Error),
    #[error(
        "configuration settings must be valid JSON, use a literal endpoint IP, and match the documented schema"
    )]
    ConfigJson(#[from] serde_json::Error),
    #[error(transparent)]
    Config(#[from] orangespace_core::tunnel::ConfigError),
    #[error("settings file is too large")]
    SettingsTooLarge,
    #[error(
        "restrictive Windows config-file ACL support is not implemented; generation is blocked on Windows"
    )]
    ConfigAclUnavailable,
}

fn data_directory(value: Option<PathBuf>) -> Result<PathBuf, Error> {
    value
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("OrangeSpace")))
        .ok_or(Error::NoDataDirectory)
}

fn execute(cli: Cli) -> Result<(Value, bool), Error> {
    let store = Store::open(&data_directory(cli.data_dir)?)?;
    let value = match cli.command {
        Command::Status { user } => json!({"schema_version":1, "ok":true,
            "browsing_allowed":false,"reason":unavailable().message,
            "sandboxes":store.list(user.map(UserId))?}),
        Command::List { user } => {
            json!({"schema_version":1,"ok":true,"sandboxes":store.list(Some(UserId(user)))?})
        }
        Command::Create { user, name } => {
            json!({"schema_version":1,"ok":true,"sandbox":store.create(UserId(user), &name)?})
        }
        Command::Bind {
            user,
            sandbox,
            node,
        } => {
            json!({"schema_version":1,"ok":true,"sandbox":store.bind(UserId(user), SandboxId(sandbox), NodeId(node))?})
        }
        Command::Close { user, sandbox } => {
            json!({"schema_version":1,"ok":true,"sandbox":store.close(UserId(user), SandboxId(sandbox))?})
        }
        Command::Delete { user, sandbox } => {
            store.delete(UserId(user), SandboxId(sandbox))?;
            json!({"schema_version":1,"ok":true,"deleted_sandbox_id":sandbox,"remote_files_deleted":false})
        }
        Command::Open { user, sandbox } => {
            let record = store.get(UserId(user), SandboxId(sandbox))?;
            let node = record.node_id.ok_or(StoreError::Unbound)?;
            let binding = Binding {
                user_id: UserId(user),
                sandbox_id: SandboxId(sandbox),
                node_id: NodeId(node),
                generation: record.generation,
                tunnel_id: TunnelId::new(),
            };
            match UnavailableGuard.authorize_browser(&binding) {
                Err(failure) => {
                    return Ok((
                        json!({"schema_version":1,"ok":false,"error":failure,"browsing_allowed":false}),
                        false,
                    ));
                }
                Ok(_) => unreachable!("UnavailableGuard cannot produce BrowserPermit"),
            }
        }
        Command::TunnelConfig {
            user,
            sandbox,
            settings_file,
            output,
        } => {
            // A configuration contains reusable credentials. Unix creates it as
            // 0600. No Windows generation until a protected ACL writer exists.
            if cfg!(windows) {
                return Err(Error::ConfigAclUnavailable);
            }
            let record = store.get(UserId(user), SandboxId(sandbox))?;
            let node = record.node_id.ok_or(StoreError::Unbound)?;
            if fs::metadata(&settings_file)?.len() > 1024 * 1024 {
                return Err(Error::SettingsTooLarge);
            }
            let settings: TunnelSettings = serde_json::from_slice(&fs::read(settings_file)?)?;
            let binding = Binding {
                user_id: UserId(user),
                sandbox_id: SandboxId(sandbox),
                node_id: NodeId(node),
                generation: record.generation,
                tunnel_id: TunnelId::new(),
            };
            let config = sing_box_config(binding, &settings)?;
            let mut options = fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&output)?;
            let content = serde_json::to_vec_pretty(&config)?;
            if let Err(error) = file.write_all(&content).and_then(|_| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(&output);
                return Err(error.into());
            }
            json!({"schema_version":1,"ok":true,"output":output,"node_id":node,
                "sandbox_id":sandbox,"generation":record.generation,
                "browsing_allowed":false,"artifact_only":true})
        }
        Command::TaskCreate { user, sandbox } => {
            json!({"schema_version":1,"ok":true,"task":store.create_task(UserId(user),SandboxId(sandbox))?})
        }
        Command::TaskList { user, sandbox } => {
            json!({"schema_version":1,"ok":true,"tasks":store.list_tasks(UserId(user),SandboxId(sandbox))?})
        }
    };
    Ok((value, true))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (value, success) = match execute(cli) {
        Ok(result) => result,
        Err(error) => {
            let code = match &error {
                Error::Store(StoreError::NotFound) => "not_found",
                Error::Store(StoreError::Unbound) => "sandbox_unbound",
                _ => "operation_failed",
            };
            (
                json!({"schema_version":1,"ok":false,"error":{"code":code,"message":error.to_string()},"browsing_allowed":false}),
                false,
            )
        }
    };
    println!("{value}");
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
