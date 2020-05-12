#![warn(missing_debug_implementations)]

#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate tokio;

use cdrs::{
    authenticators::StaticPasswordAuthenticator,
    cluster::{session::Session, TcpConnectionPool},
    load_balancing::RoundRobin,
};

/// DbSession represents a Scylla database session.
pub type DbSession = Session<RoundRobin<TcpConnectionPool<StaticPasswordAuthenticator>>>;

/// Schema describes the swaply identity service database schema.
pub mod schema;
