use crate::Binding;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct GuardFailure {
    pub code: &'static str,
    pub message: &'static str,
}

/// This API will be implemented by the Windows service after kernel enforcement
/// is available. A proof cannot be constructed by deserializing UI settings.
pub trait GuardBackend {
    fn authorize_browser(&self, binding: &Binding) -> Result<BrowserPermit, GuardFailure>;
}

/// Private fields prevent callers from fabricating a successful guard result.
pub struct BrowserPermit {
    _binding: Binding,
}

pub struct UnavailableGuard;

impl GuardBackend for UnavailableGuard {
    fn authorize_browser(&self, _binding: &Binding) -> Result<BrowserPermit, GuardFailure> {
        Err(unavailable())
    }
}

pub fn unavailable() -> GuardFailure {
    GuardFailure {
        code: "guard_unavailable",
        message: "Browsing is blocked: signed WFP TCP/UDP enforcement, DNS containment and process identity validation are not implemented and verified.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, SandboxId, TunnelId, UserId};

    #[test]
    fn unavailable_guard_never_grants_a_browser_permit() {
        let binding = Binding {
            user_id: UserId::new(),
            sandbox_id: SandboxId::new(),
            node_id: NodeId::new(),
            generation: 1,
            tunnel_id: TunnelId::new(),
        };
        assert!(UnavailableGuard.authorize_browser(&binding).is_err());
    }
}
