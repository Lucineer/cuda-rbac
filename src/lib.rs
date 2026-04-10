/*!
# cuda-rbac

Role-based access control for agents.

Not every agent should do everything. RBAC defines who can do what
through roles and permissions, with inheritance and wildcard support.

- Roles with permission sets
- Permission inheritance (child roles include parent)
- Agent-role assignment
- Capability checks
- Wildcard permissions
- Permission deny rules (override allow)
*/

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A permission
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    pub resource: String,
    pub action: String,
}

impl Permission {
    pub fn new(resource: &str, action: &str) -> Self { Permission { resource: resource.to_string(), action: action.to_string() } }
    /// Wildcard: "sensor:*" means any action on sensor
    pub fn matches(&self, other: &Permission) -> bool {
        let resource_match = self.resource == "*" || self.resource == other.resource;
        let action_match = self.action == "*" || self.action == other.action;
        resource_match && action_match
    }
}

/// A role
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: HashSet<Permission>,
    pub parent: Option<String>,
    pub deny_rules: HashSet<Permission>,
    pub description: String,
}

impl Role {
    pub fn new(name: &str) -> Self { Role { name: name.to_string(), permissions: HashSet::new(), parent: None, deny_rules: HashSet::new(), description: String::new() } }
    pub fn with_permission(mut self, resource: &str, action: &str) -> Self { self.permissions.insert(Permission::new(resource, action)); self }
    pub fn with_parent(mut self, parent: &str) -> Self { self.parent = Some(parent.to_string()); self }
    pub fn with_deny(mut self, resource: &str, action: &str) -> Self { self.deny_rules.insert(Permission::new(resource, action)); self }
}

/// An agent's RBAC profile
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentProfile {
    pub agent_id: String,
    pub roles: HashSet<String>,
    pub direct_permissions: HashSet<Permission>,
    pub active: bool,
}

/// Check result
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessResult { Allowed, DeniedByRole, DeniedByPolicy, NoPermission, Inactive }

/// The RBAC system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RbacSystem {
    pub roles: HashMap<String, Role>,
    pub profiles: HashMap<String, AgentProfile>,
    pub total_checks: u64,
    pub allowed: u64,
    pub denied: u64,
}

impl RbacSystem {
    pub fn new() -> Self { RbacSystem { roles: HashMap::new(), profiles: HashMap::new(), total_checks: 0, allowed: 0, denied: 0 } }

    /// Create a role
    pub fn create_role(&mut self, role: Role) { self.roles.insert(role.name.clone(), role); }

    /// Assign role to agent
    pub fn assign_role(&mut self, agent_id: &str, role_name: &str) {
        let profile = self.profiles.entry(agent_id.to_string()).or_insert_with(|| AgentProfile { agent_id: agent_id.to_string(), roles: HashSet::new(), direct_permissions: HashSet::new(), active: true });
        profile.roles.insert(role_name.to_string());
    }

    /// Revoke role
    pub fn revoke_role(&mut self, agent_id: &str, role_name: &str) {
        if let Some(profile) = self.profiles.get_mut(agent_id) { profile.roles.remove(role_name); }
    }

    /// Grant direct permission
    pub fn grant_permission(&mut self, agent_id: &str, resource: &str, action: &str) {
        let profile = self.profiles.entry(agent_id.to_string()).or_insert_with(|| AgentProfile { agent_id: agent_id.to_string(), roles: HashSet::new(), direct_permissions: HashSet::new(), active: true });
        profile.direct_permissions.insert(Permission::new(resource, action));
    }

    /// Collect all effective permissions for an agent (including inherited)
    pub fn effective_permissions(&self, agent_id: &str) -> HashSet<Permission> {
        let profile = match self.profiles.get(agent_id) { Some(p) => p, None => return HashSet::new() };
        let mut perms: HashSet<Permission> = profile.direct_permissions.clone();

        // Role permissions with inheritance
        let mut visited = HashSet::new();
        for role_name in &profile.roles {
            self.collect_role_perms(role_name, &mut perms, &mut visited);
        }
        perms
    }

    fn collect_role_perms(&self, role_name: &str, perms: &mut HashSet<Permission>, visited: &mut HashSet<String>) {
        if visited.contains(role_name) { return; }
        visited.insert(role_name.to_string());
        if let Some(role) = self.roles.get(role_name) {
            perms.extend(role.permissions.iter().cloned());
            if let Some(ref parent) = role.parent { self.collect_role_perms(parent, perms, visited); }
        }
    }

    /// Collect all deny rules for an agent
    fn deny_rules(&self, agent_id: &str) -> HashSet<Permission> {
        let profile = match self.profiles.get(agent_id) { Some(p) => p, None => return HashSet::new() };
        let mut denies = HashSet::new();
        let mut visited = HashSet::new();
        for role_name in &profile.roles {
            self.collect_role_denies(role_name, &mut denies, &mut visited);
        }
        denies
    }

    fn collect_role_denies(&self, role_name: &str, denies: &mut HashSet<Permission>, visited: &mut HashSet<String>) {
        if visited.contains(role_name) { return; }
        visited.insert(role_name.to_string());
        if let Some(role) = self.roles.get(role_name) {
            denies.extend(role.deny_rules.iter().cloned());
            if let Some(ref parent) = role.parent { self.collect_role_denies(parent, denies, visited); }
        }
    }

    /// Check if an agent has permission
    pub fn check(&mut self, agent_id: &str, resource: &str, action: &str) -> AccessResult {
        self.total_checks += 1;
        let profile = match self.profiles.get(agent_id) {
            Some(p) if p.active => p,
            Some(_) => { self.denied += 1; return AccessResult::Inactive; },
            None => { self.denied += 1; return AccessResult::NoPermission; },
        };

        let requested = Permission::new(resource, action);

        // Check deny rules first (deny overrides allow)
        let denies = self.deny_rules(agent_id);
        for deny in &denies {
            if deny.matches(&requested) { self.denied += 1; return AccessResult::DeniedByPolicy; }
        }

        // Check permissions
        let effective = self.effective_permissions(agent_id);
        for perm in &effective {
            if perm.matches(&requested) { self.allowed += 1; return AccessResult::Allowed; }
        }

        self.denied += 1;
        AccessResult::NoPermission
    }

    /// Get all roles
    pub fn all_roles(&self) -> Vec<&str> { self.roles.keys().map(|k| k.as_str()).collect() }

    /// Get agents with a role
    pub fn agents_with_role(&self, role: &str) -> Vec<&str> {
        self.profiles.values().filter(|p| p.roles.contains(role)).map(|p| p.agent_id.as_str()).collect()
    }

    /// Summary
    pub fn summary(&self) -> String {
        format!("RBAC: {} roles, {} agents, checks={} (allowed={}, denied={})",
            self.roles.len(), self.profiles.len(), self.total_checks, self.allowed, self.denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_permission() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("reader").with_permission("document", "read"));
        rbac.assign_role("a1", "reader");
        assert_eq!(rbac.check("a1", "document", "read"), AccessResult::Allowed);
    }

    #[test]
    fn test_permission_denied() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("reader").with_permission("document", "read"));
        rbac.assign_role("a1", "reader");
        assert_eq!(rbac.check("a1", "document", "write"), AccessResult::NoPermission);
    }

    #[test]
    fn test_wildcard_permission() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("admin").with_permission("document", "*"));
        rbac.assign_role("a1", "admin");
        assert_eq!(rbac.check("a1", "document", "write"), AccessResult::Allowed);
        assert_eq!(rbac.check("a1", "document", "delete"), AccessResult::Allowed);
    }

    #[test]
    fn test_role_inheritance() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("base").with_permission("system", "read"));
        rbac.create_role(Role::new("admin").with_permission("system", "write").with_parent("base"));
        rbac.assign_role("a1", "admin");
        assert_eq!(rbac.check("a1", "system", "read"), AccessResult::Allowed); // inherited
        assert_eq!(rbac.check("a1", "system", "write"), AccessResult::Allowed); // own
    }

    #[test]
    fn test_deny_overrides_allow() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("restricted").with_permission("data", "read").with_deny("data", "sensitive"));
        rbac.assign_role("a1", "restricted");
        assert_eq!(rbac.check("a1", "data", "read"), AccessResult::Allowed);
        assert_eq!(rbac.check("a1", "data", "sensitive"), AccessResult::DeniedByPolicy);
    }

    #[test]
    fn test_direct_permission() {
        let mut rbac = RbacSystem::new();
        rbac.grant_permission("a1", "special", "action");
        assert_eq!(rbac.check("a1", "special", "action"), AccessResult::Allowed);
    }

    #[test]
    fn test_inactive_agent() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("reader").with_permission("x", "read"));
        rbac.assign_role("a1", "reader");
        rbac.profiles.get_mut("a1").unwrap().active = false;
        assert_eq!(rbac.check("a1", "x", "read"), AccessResult::Inactive);
    }

    #[test]
    fn test_multiple_roles() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("reader").with_permission("doc", "read"));
        rbac.create_role(Role::new("writer").with_permission("doc", "write"));
        rbac.assign_role("a1", "reader");
        rbac.assign_role("a1", "writer");
        assert_eq!(rbac.check("a1", "doc", "read"), AccessResult::Allowed);
        assert_eq!(rbac.check("a1", "doc", "write"), AccessResult::Allowed);
    }

    #[test]
    fn test_agents_with_role() {
        let mut rbac = RbacSystem::new();
        rbac.create_role(Role::new("admin"));
        rbac.assign_role("a1", "admin");
        rbac.assign_role("a2", "admin");
        rbac.assign_role("a3", "reader");
        let admins = rbac.agents_with_role("admin");
        assert_eq!(admins.len(), 2);
    }

    #[test]
    fn test_summary() {
        let rbac = RbacSystem::new();
        let s = rbac.summary();
        assert!(s.contains("0 roles"));
    }
}
