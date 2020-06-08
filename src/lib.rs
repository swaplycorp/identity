#![warn(missing_debug_implementations)]

#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate async_trait;

use cdrs::{
    authenticators::StaticPasswordAuthenticator,
    cluster::{session::Session, TcpConnectionPool},
    load_balancing::RoundRobin,
    query::QueryExecutor,
};
use result::IdentityResult;

/// Schema describes the swaply identity service database schema.
pub mod schema;

/// Server implements a capnproto RPC and REST/JSON-HTTP identity service server.
pub mod server;

/// Db defines various database helper methods and types.
pub mod db;

/// DbSession represents a Scylla database session.
pub type DbSession = Session<RoundRobin<TcpConnectionPool<StaticPasswordAuthenticator>>>;

/// Result implements helpful error types.
pub mod result {
    use super::error::IdentityError;
    use std::result::Result as StdResult;

    /// IdentityResult represents the result of a computation that may or may not fail.
    pub type IdentityResult<T> = StdResult<T, IdentityError>;
}

pub mod error {
    use cdrs::error::Error as CDRSError;
    use regex::Error as RegexError;

    /// Error represents any error emitted by the swaply identity service.
    #[derive(Debug)]
    pub enum IdentityError {
        QueryError(QueryError),
        InsertionError(InsertionError),
        TableError(TableError),
    }

    impl From<QueryError> for IdentityError {
        fn from(e: QueryError) -> Self {
            Self::QueryError(e)
        }
    }

    impl From<InsertionError> for IdentityError {
        fn from(e: InsertionError) -> Self {
            Self::InsertionError(e)
        }
    }

    impl From<TableError> for IdentityError {
        fn from(e: TableError) -> Self {
            Self::TableError(e)
        }
    }

    /// QueryError represents any error that may be encountered while querying the database.
    #[derive(Debug)]
    pub enum QueryError {
        NoResults,
        CDRSError(CDRSError),
    }

    impl From<CDRSError> for QueryError {
        fn from(e: CDRSError) -> Self {
            Self::CDRSError(e)
        }
    }

    /// InsertionError represents any error that may be encountered whilst inserting a value into a
    /// database.
    #[derive(Debug)]
    pub enum InsertionError {
        CDRSError(CDRSError),
        RegexError(RegexError),
    }

    impl From<CDRSError> for InsertionError {
        fn from(e: CDRSError) -> Self {
            Self::CDRSError(e)
        }
    }

    /// TableError represents any error that may be encountered whilst creating or modifying a table.
    #[derive(Debug)]
    pub enum TableError {
        CDRSError(CDRSError),
    }

    impl From<CDRSError> for TableError {
        fn from(e: CDRSError) -> Self {
            Self::CDRSError(e)
        }
    }
}

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
pub async fn create_keyspace(session: &mut DbSession) -> IdentityResult<()> {
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
        .map_err(|e| error::TableError::CDRSError(e).into())
        .map(|_| ())
}
