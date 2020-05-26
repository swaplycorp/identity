#![warn(missing_debug_implementations)]

#[macro_use]
extern crate arrayref;

use cdrs::{
    authenticators::StaticPasswordAuthenticator,
    cluster::{session::Session, TcpConnectionPool},
    load_balancing::RoundRobin,
    Result as CDRSResult,
    query::QueryExecutor
};

/// Schema describes the swaply identity service database schema.
pub mod schema;

/// Server implements a capnproto RPC and REST/JSON-HTTP identity service server.
pub mod server;

/// DbSession represents a Scylla database session.
pub type DbSession = Session<RoundRobin<TcpConnectionPool<StaticPasswordAuthenticator>>>;

/// Creates the identity keyspace in the scylla instance.
///
/// # Arguments
///
/// * `session` - The scylla db connector that shouold be used
///
/// # Examples
///
/// ```
/// use cdrs::{authenticators::StaticPasswordAuthenticator, cluster::{NodeTcpConfigBuilder, ClusterTcpConfig}, load_balancing::RoundRobin};
/// use std::{env, error::Error};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn Error>> {
/// # dotenv::dotenv()?;
///
/// let db_node = env::var("SCYLLA_NODE_URL")?;
///
///
/// let auth = StaticPasswordAuthenticator::new(env::var("SCYLLA_USERNAME")?, env::var("SCYLLA_PASSWORD")?);
/// let node = NodeTcpConfigBuilder::new(&db_node, auth).build();
/// let cluster_config = ClusterTcpConfig(vec![node]);
/// let mut session = cdrs::cluster::session::new(&cluster_config, RoundRobin::new()).await?;
///
/// swaply_identity::create_keyspace(&mut session).await?;
///
/// Ok(())
/// # }
/// ```
pub async fn create_keyspace(session: &mut DbSession) -> CDRSResult<()> {
    session
        .query(
            r#"
            CREATE KEYSPACE IF NOT EXISTS identity
                WITH REPLICATION = {
                    'class': 'SimpleStrategy',
                    'replication_factor': 1
            };
            "#,
        )
        .await
        .map(|_| ())
}
