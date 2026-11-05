use crate::{Binding, NodeId, SandboxId, TunnelId, UserId};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RouteError {
    #[error("sandbox not found for authenticated user")]
    NotFound,
    #[error("sandbox already exists")]
    AlreadyExists,
    #[error("tunnel is offline or this binding is stale")]
    Offline,
    #[error("flow already exists")]
    DuplicateFlow,
    #[error("identifier space exhausted")]
    Exhausted,
}

struct Sandbox {
    user: UserId,
    generation: u64,
    binding: Option<Binding>,
    connected: bool,
    tcp: HashMap<u64, u64>,
    used_tcp: HashSet<u64>,
    udp_by_socket: HashMap<u64, u16>,
    udp_by_association: HashMap<u16, u64>,
    next_udp: u32,
}

impl Sandbox {
    fn clear_flows(&mut self) {
        self.tcp.clear();
        self.used_tcp.clear();
        self.udp_by_socket.clear();
        self.udp_by_association.clear();
        self.next_udp = 0;
    }
}

/// A sandbox owns a tunnel; no process-global "current node" exists.
#[derive(Default)]
pub struct Router {
    sandboxes: HashMap<SandboxId, Sandbox>,
}

impl Router {
    pub fn create(&mut self, user: UserId, id: SandboxId) -> Result<(), RouteError> {
        if self.sandboxes.contains_key(&id) {
            return Err(RouteError::AlreadyExists);
        }
        self.sandboxes.insert(
            id,
            Sandbox {
                user,
                generation: 0,
                binding: None,
                connected: false,
                tcp: HashMap::new(),
                used_tcp: HashSet::new(),
                udp_by_socket: HashMap::new(),
                udp_by_association: HashMap::new(),
                next_udp: 0,
            },
        );
        Ok(())
    }

    fn owned_mut(&mut self, user: UserId, id: SandboxId) -> Result<&mut Sandbox, RouteError> {
        self.sandboxes
            .get_mut(&id)
            .filter(|s| s.user == user)
            .ok_or(RouteError::NotFound)
    }

    /// Invalidate old flows before a new helper/handshake is started.
    pub fn begin_tunnel(
        &mut self,
        user: UserId,
        id: SandboxId,
        node: NodeId,
    ) -> Result<Binding, RouteError> {
        let s = self.owned_mut(user, id)?;
        let generation = s.generation.checked_add(1).ok_or(RouteError::Exhausted)?;
        let binding = Binding {
            user_id: user,
            sandbox_id: id,
            node_id: node,
            generation,
            tunnel_id: TunnelId::new(),
        };
        s.connected = false;
        s.clear_flows();
        s.generation = generation;
        s.binding = Some(binding);
        Ok(binding)
    }

    /// A transport handshake result does not grant permission to launch browsers.
    pub fn transport_connected(&mut self, binding: Binding) -> Result<(), RouteError> {
        let s = self.current_mut(binding, false)?;
        s.connected = true;
        Ok(())
    }

    fn current_mut(
        &mut self,
        binding: Binding,
        must_be_connected: bool,
    ) -> Result<&mut Sandbox, RouteError> {
        let s = self.owned_mut(binding.user_id, binding.sandbox_id)?;
        if s.binding != Some(binding) || (must_be_connected && !s.connected) {
            return Err(RouteError::Offline);
        }
        Ok(s)
    }

    fn current(&self, binding: Binding) -> Result<&Sandbox, RouteError> {
        self.sandboxes
            .get(&binding.sandbox_id)
            .filter(|s| s.user == binding.user_id && s.binding == Some(binding) && s.connected)
            .ok_or(RouteError::Offline)
    }

    pub fn disconnect(&mut self, binding: Binding) -> Result<(), RouteError> {
        let s = self.current_mut(binding, false)?;
        s.connected = false;
        s.clear_flows();
        // Reject even a late successful handshake for the disconnected epoch.
        s.binding = None;
        Ok(())
    }

    pub fn close(&mut self, user: UserId, id: SandboxId) -> Result<(), RouteError> {
        let s = self.owned_mut(user, id)?;
        s.connected = false;
        s.binding = None;
        s.clear_flows();
        Ok(())
    }

    pub fn delete(&mut self, user: UserId, id: SandboxId) -> Result<(), RouteError> {
        self.owned_mut(user, id)?;
        self.sandboxes.remove(&id);
        Ok(())
    }

    /// stream_id is scoped to the exact tunnel; browser_socket is an opaque
    /// broker-owned socket identity, never an untrusted caller's raw handle.
    pub fn register_tcp(
        &mut self,
        binding: Binding,
        stream_id: u64,
        browser_socket: u64,
    ) -> Result<(), RouteError> {
        let s = self.current_mut(binding, true)?;
        if !s.used_tcp.insert(stream_id) {
            return Err(RouteError::DuplicateFlow);
        }
        s.tcp.insert(stream_id, browser_socket);
        Ok(())
    }

    pub fn resolve_tcp(&self, binding: Binding, stream_id: u64) -> Result<u64, RouteError> {
        self.current(binding)?
            .tcp
            .get(&stream_id)
            .copied()
            .ok_or(RouteError::Offline)
    }

    pub fn remove_tcp(&mut self, binding: Binding, stream_id: u64) -> Result<(), RouteError> {
        self.current_mut(binding, true)?.tcp.remove(&stream_id);
        Ok(())
    }

    /// Reuse one TUIC association for the original UDP socket across destinations
    /// (important for STUN/NAT behavior). Never key this map by destination alone.
    pub fn udp_association(
        &mut self,
        binding: Binding,
        browser_socket: u64,
    ) -> Result<u16, RouteError> {
        let s = self.current_mut(binding, true)?;
        if let Some(id) = s.udp_by_socket.get(&browser_socket) {
            return Ok(*id);
        }
        let id = u16::try_from(s.next_udp).map_err(|_| RouteError::Exhausted)?;
        s.next_udp += 1;
        s.udp_by_socket.insert(browser_socket, id);
        s.udp_by_association.insert(id, browser_socket);
        Ok(id)
    }

    pub fn resolve_udp(&self, binding: Binding, association: u16) -> Result<u64, RouteError> {
        self.current(binding)?
            .udp_by_association
            .get(&association)
            .copied()
            .ok_or(RouteError::Offline)
    }

    pub fn remove_udp(&mut self, binding: Binding, browser_socket: u64) -> Result<(), RouteError> {
        let s = self.current_mut(binding, true)?;
        if let Some(id) = s.udp_by_socket.remove(&browser_socket) {
            s.udp_by_association.remove(&id);
        }
        // Never reuse association IDs in the same tunnel: late datagrams would
        // otherwise be delivered to a different original socket.
        Ok(())
    }
}
