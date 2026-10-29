//! Control-plane invariants. This crate does not capture packets or enforce WFP.
pub mod guard;
pub mod routing;
pub mod tunnel;

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

id!(UserId);
id!(SandboxId);
id!(NodeId);
id!(TunnelId);
id!(TransferId);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    pub user_id: UserId,
    pub sandbox_id: SandboxId,
    pub node_id: NodeId,
    pub generation: u64,
    pub tunnel_id: TunnelId,
}

/// File task destination is captured at creation and has no rebinding operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransferTarget {
    id: TransferId,
    user_id: UserId,
    sandbox_id: SandboxId,
    node_id: NodeId,
}

impl TransferTarget {
    pub fn from_binding(binding: Binding) -> Self {
        Self {
            id: TransferId::new(),
            user_id: binding.user_id,
            sandbox_id: binding.sandbox_id,
            node_id: binding.node_id,
        }
    }
    pub fn id(&self) -> TransferId {
        self.id
    }
    pub fn user_id(&self) -> UserId {
        self.user_id
    }
    pub fn sandbox_id(&self) -> SandboxId {
        self.sandbox_id
    }
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }
}
