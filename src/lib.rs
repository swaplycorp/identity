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

/// Testing defines utilities useful in testing swaply identity features.
#[cfg(test)]
pub(crate) mod testing {
    use cdrs::{
        cluster::{ClusterTcpConfig, NodeTcpConfigBuilder},
        load_balancing::RoundRobin,
    };
    use std::{env, error::Error};

    use super::{
        db::{Insertable, Provider, Serializable},
        schema::user::User,
        *,
    };

    /// Represents a default password utilized by the generate_user method.
    const TEST_PASSWORD_HASH: &'static [u8] = b"123456";

    // If a .env file doesn't exist, fallback to env variables
    #[macro_export]
    macro_rules! load_env {
        () => {{
            if std::path::Path::new(".env").exists() {
                dotenv::dotenv().ok();
            }
        }};
    }

    /// Opens a connection to the scylla databse defined by a .env file, or simple environment
    /// variables.
    pub async fn open_session() -> Result<DbSession, Box<dyn Error>> {
        load_env!();

        let db_node = env::var("SCYLLA_NODE_URL")?;

        let auth = StaticPasswordAuthenticator::new(
            env::var("SCYLLA_USERNAME")?,
            env::var("SCYLLA_PASSWORD")?,
        );

        let node = NodeTcpConfigBuilder::new(&db_node, auth).build();
        let cluster_config = ClusterTcpConfig(vec![node]);
        cdrs::cluster::session::new(&cluster_config, RoundRobin::new())
            .await
            .map_err(|e| e.into())
    }

    /// Inserts the provided user into the provided database session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session that the user should be inserted into
    pub async fn insert_user<'a, Db: Provider<Db, Session>, Session>(
        session: &Db,
        u: &User<'a>,
    ) -> Result<(), error::IdentityError>
    where
        User<'a>: Insertable<Db, Session> + Serializable<Db::RequestIntermediary>,
    {
        session.insert_record(u).await
    }

    /// Generates an instance of the User struct.
    pub fn generate_user<'a>() -> User<'a> {
        User::new(
            None,
            "test",
            "test@test.com",
            blake3::hash(TEST_PASSWORD_HASH).into(),
            None,
        )
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
    use std::{error::Error, fmt};

    use super::schema::user::{ConvertRowToUserError, ConvertUserToQueryValuesError};

    /// Error represents any error emitted by the swaply identity service.
    #[derive(Debug)]
    pub enum IdentityError {
        QueryError(QueryError),
        CDRSError(CDRSError),
    }

    impl From<QueryError> for IdentityError {
        fn from(e: QueryError) -> Self {
            Self::QueryError(e)
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
                Self::CDRSError(e) => Some(e),
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
/// # if std::path::Path::new(".env").exists() {
/// #     dotenv::dotenv().ok();
/// # }
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
