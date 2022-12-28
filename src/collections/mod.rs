//! Common collection traits.
//!
//! # TODO: Use the `cc-traits` crate.
//!
//! - Add support for `no_std`, `heapless`, `Map::retain`, etc.
//!
//! This way users can use other collections not implemented here, and
//! cc-traits has several implementations for other collections from
//! other crates.
//!
//! So, in short, remove this module.

mod deque;
mod set;
mod vec;

pub use self::deque::*;
pub use self::set::*;
pub use self::vec::*;
