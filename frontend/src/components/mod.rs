//! Presentational + stateful components for the LuxShield console.
//!
//! Each is annotated with `#[component]`, which synthesises a `<Name>Props`
//! struct per parameter. Shared state is never threaded as props — components
//! pull the single `AppState` out of context with `use_context`.

pub mod control_panel;
pub mod firewall_panel;
pub mod metrics_bar;
pub mod packet_terminal;
pub mod toast_stack;
pub mod top_bar;
pub mod traffic_map;

// Glob re-export: `view!` references both the component function and its
// generated `<Name>Props` struct, so a single `use crate::components::*;`
// brings everything into scope.
pub use control_panel::*;
pub use firewall_panel::*;
pub use metrics_bar::*;
pub use packet_terminal::*;
pub use toast_stack::*;
pub use top_bar::*;
pub use traffic_map::*;
