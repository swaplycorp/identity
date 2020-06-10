#![warn(missing_debug_implementations)]

#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate async_trait;

use cdrs::{
    authenticators::StaticPasswordAuthenticator,
    cluster::{session::Session, TcpConnectionPool},
    error::Error as CDRSError,
    load_balancing::RoundRobin,
    query::QueryExecutor,
};

/// Schema describes the swaply identity service database schema.
pub mod schema;

/// Server implements a capnproto RPC and REST/JSON-HTTP identity service server.
pub mod server;

/// Db defines various database helper methods and types.
pub mod db;

/// DbSession represents a Scylla database session.
pub type DbSession = Session<RoundRobin<TcpConnectionPool<StaticPasswordAuthenticator>>>;

mod testing {
    // If a .env file doesn't exist, fallback to env variables
    #[macro_export]
    macro_rules! load_env {
        () => {{
            if std::path::Path::new(".env").exists() {
                dotenv::dotenv().ok();
            }
        }};
    }
}

/// Result implements helpful Ok/Err types.
pub mod result {
    use super::error::IdentityError;
    use std::result::Result as StdResult;

    /// IdentityResult represents the result of a computation that may or may not fail.
    pub type IdentityResult<T> = StdResult<T, IdentityError>;
}

/// Error implements helpful error types.
pub mod error {
    use cdrs::error::Error as CDRSError;
    use regex::Error as RegexError;
    use std::{error::Error, fmt};

    use super::schema::user::{ConvertRowToUserError, ConvertUserToQueryValuesError};

    /// Error represents any error emitted by the swaply identity service.
    #[derive(Debug)]
    pub enum IdentityError {
        QueryError(QueryError),
        InsertionError(InsertionError),
        CDRSError(CDRSError),
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

    impl From<CDRSError> for IdentityError {
        fn from(e: CDRSError) -> Self {
            Self::CDRSError(e)
        }
    }

    impl fmt::Display for IdentityError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "encountered an error: {:?}", self.source())
        }
    }

    impl Error for IdentityError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::QueryError(e) => Some(e),
                Self::InsertionError(e) => Some(e),
                Self::CDRSError(e) => Some(e)
            }
        }
    }

    /// QueryError represents any error that may be encountered while querying the database.
    #[derive(Debug)]
    pub enum QueryError {
        NoResults,
        SerializationError(ConvertUserToQueryValuesError),
        DeserializationError(ConvertRowToUserError),
    }

    impl fmt::Display for QueryError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "encountered an error while querying the database: {}",
                match self {
                    Self::NoResults => "no results found".to_owned(),
                    _ => format!("{:?}", self.source()),
                }
            )
        }
    }

    impl Error for QueryError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::NoResults => None,
                Self::SerializationError(e) => Some(e),
                Self::DeserializationError(e) => Some(e),
            }
        }
    }

    /// InsertionError represents any error that may be encountered whilst inserting a value into a
    /// database.
    #[derive(Debug)]
    pub enum InsertionError {
        RegexError(RegexError),
    }

    impl fmt::Display for InsertionError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "encountered an error while inserting a record into a table: {:?}",
                self.source()
            )
        }
    }

    impl Error for InsertionError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::RegexError(e) => Some(e),
            }
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
/// # swaply_identity::load_env!();
///
/// let db_node = env::var("SCYLLA_NODE_URL")?;
///
/// let auth = StaticPasswordAuthenticator::new(env::var("SCYLLA_USERNAME")?, env::var("SCYLLA_PASSWORD")?);
/// let node = NodeTcpConfigBuilder::new(&db_node, auth).build();
/// let cluster_config = ClusterTcpConfig(vec![node]);
/// let session = cdrs::cluster::session::new(&cluster_config, RoundRobin::new()).await?;
///
/// swaply_identity::create_keyspace(&session).await?;
///
/// Ok(())
/// # }
/// ```
pub async fn create_keyspace(session: &DbSession) -> result::IdentityResult<()> {
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
        .map_err(|e| <CDRSError as Into<error::IdentityError>>::into(e))
        .map(|_| ())
}
