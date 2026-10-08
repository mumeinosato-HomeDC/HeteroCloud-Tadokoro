//! Tadokoro: the HeteroCloud `provider/v1` service for Proxmox VE virtual machines.
//!
//! The provider is stateless. Every piece of desired and observed state lives on
//! the Proxmox VM itself (name suffix, tags and description), so a restart never
//! loses accepted work and `PUT` is an idempotent "advance towards generation N"
//! step that the HeteroCloud worker repeats until the provider answers `202`.

pub mod api;
pub mod auth;
pub mod config;
pub mod ipam;
pub mod pve;
pub mod reconcile;
pub mod spec;

pub const PROVIDER_RECONCILE_ACTION: &str = "service-instance.reconcile";
pub const PROVIDER_DELETE_ACTION: &str = "service-instance.delete";
pub const PROVIDER_STATUS_GET_ACTION: &str = "vm.status.get";
