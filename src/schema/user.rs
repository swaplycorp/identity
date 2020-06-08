use bincode::Error as BincodeError;
use bs58::encode::Error as Bs58EncodingError;
use cdrs::{
    error::Error as CDRSError,
    frame::traits::TryFromRow,
    query::{QueryExecutor, QueryValues},
    query_values,
    types::{blob::Blob, prelude::Row, value::Bytes, IntoRustByIndex, IntoRustByName},
    Result as CDRSResult,
};
use chrono::{naive::NaiveDateTime, DateTime, Utc};
use serde::{Deserialize, Serialize};
use time::Timespec;
use uuid::Uuid;

use super::super::{
    db::{
        scylla::{InTable, Scylla},
        Queryable,
        Serializable
    },
    error::{IdentityError, QueryError, TableError},
    result::IdentityResult,
    DbSession,
};

use std::{
    convert::{TryFrom, TryInto},
    error::Error,
    fmt,
    num::TryFromIntError,
};

/// IdentityProvider represents any arbitrary provider of an authorization or
/// authentication service (i.e., a provider of an OpenID Connection-capable
/// identity API).
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum IdentityProvider {
    /// Google provides an OpenID connect OAuth 2.0 API: https://developers.google.com/identity/protocols/oauth2/openid-connect.
    /// As does twitch, Google returns IDs as "sub" claims--strings.
    Google,

    /// GitHub also provides an OAuth 2.0 API, but uses non-standard endpoints: https://fusionauth.io/docs/v1/tech/identity-providers/openid-connect/github
    /// Also, their docs are pretty unclear, which doesn't help. IDs are
    /// returned as integers in the GitHub oauth API.
    GitHub,

    /// Twitch has excellent OpenID connect integration: https://dev.twitch.tv/docs/authentication/getting-tokens-oidc.
    /// User IDs are returned in the "sub" OpenID connect claim, and are
    /// returned as strings.
    Twitch,

    /// Reddit doesn't have support for OpenID connect, but does have a
    /// /api/v1/me route that we can use to get the ID of a user. In the
    /// Reddit user API, IDs are stored as SERIAL strings.
    Reddit,

    /// Twitter's docs are pretty god-awful. Here's a route we can use to get
    /// a user ID from an access token: https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials.
    /// In the Twitter user API, IDs are stored as large unsigned integers.
    Twitter,

    /// In contrast to Twitter, Discord's docs are pretty top-tier. Here's how
    /// we can identify a user:
    /// https://discord.com/developers/docs/resources/user#get-current-user.
    /// For the discord identity provider, we'll want to use a string to store
    /// IDs.
    Discord,

    /// We can use a Facebook access token to obtain some data regarding a user
    /// by sending a GET to this URL: graph.facebook.com/debug_token?input_token={token-to-inspect}
    Facebook,
}

/// IntoIdentityProviderError represents an error that may be encountered while parsing a type into
/// an IdentityProvider.
#[derive(Debug)]
pub enum IntoIdentityProviderError {
    Utf8Error(std::str::Utf8Error),
    InvalidProvider,
}

impl TryFrom<&[u8]> for IdentityProvider {
    type Error = IntoIdentityProviderError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(bytes)
            .map_err(|e| IntoIdentityProviderError::Utf8Error(e))
            .and_then(|str_identity_provider| str_identity_provider.try_into())
    }
}

impl From<IdentityProvider> for Bytes {
    fn from(id: IdentityProvider) -> Self {
        <&str as From<IdentityProvider>>::from(id).into()
    }
}

impl From<IdentityProvider> for &[u8] {
    fn from(id: IdentityProvider) -> Self {
        <&str as From<IdentityProvider>>::from(id).as_bytes()
    }
}

impl From<IdentityProvider> for &str {
    fn from(id: IdentityProvider) -> Self {
        match id {
            IdentityProvider::Google => "google",
            IdentityProvider::GitHub => "github",
            IdentityProvider::Twitch => "twitch",
            IdentityProvider::Reddit => "reddit",
            IdentityProvider::Twitter => "twitter",
            IdentityProvider::Discord => "discord",
            IdentityProvider::Facebook => "facebook",
        }
    }
}

impl TryFrom<String> for IdentityProvider {
    type Error = IntoIdentityProviderError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        <Self as TryFrom<&str>>::try_from(&s)
    }
}

impl TryFrom<&str> for IdentityProvider {
    type Error = IntoIdentityProviderError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "google" => Ok(Self::Google),
            "github" => Ok(Self::GitHub),
            "twitch" => Ok(Self::Twitch),
            "twitter" => Ok(Self::Twitter),
            "discord" => Ok(Self::Discord),
            "facebook" => Ok(Self::Facebook),
            _ => Err(Self::Error::InvalidProvider),
        }
    }
}

/* Timespecs themselves don't implement conversions to and from cdrs types (i.e., Bytes), so we
 * need to do it ourselves by rolling a custom RegistrationTimestamp struct. */

/// RegistrationTimestamp represents a timestamp for a user registration (UTC).
#[derive(Copy, Clone, Default, Serialize, Deserialize, Debug)]
pub struct RegistrationTimestamp {
    sec: i64,
    nsec: i32,
}

impl RegistrationTimestamp {
    /// Gets the number of whole seconds since January 1, 1970 represented by this timestamp.
    pub fn seconds(&self) -> i64 {
        self.sec
    }

    /// Gets the number of remaining nanoseconds since January 1, 1970 represented by this
    /// timestamp.
    pub fn nanoseconds(&self) -> i32 {
        self.nsec
    }
}

// Conversion from a Timespec to a RegistrationTimestamp
impl From<Timespec> for RegistrationTimestamp {
    fn from(timestamp: Timespec) -> Self {
        Self {
            sec: timestamp.sec,
            nsec: timestamp.nsec,
        }
    }
}

// Conversion from a RegistrationTimestamp to a Timespec
impl From<&RegistrationTimestamp> for Timespec {
    fn from(timestamp: &RegistrationTimestamp) -> Self {
        Self {
            sec: timestamp.sec,
            nsec: timestamp.nsec,
        }
    }
}

// In case you want to convert from an owned RegistrationTimestamp to a Timespec
impl From<RegistrationTimestamp> for Timespec {
    fn from(timestamp: RegistrationTimestamp) -> Self {
        <&RegistrationTimestamp as Into<Timespec>>::into(&timestamp)
    }
}

// Conversion from a RegistrationTimestamp to a DateTime (preferred representation in rust code,
// since it has a really nice API)
impl From<&RegistrationTimestamp> for DateTime<Utc> {
    fn from(timestamp: &RegistrationTimestamp) -> Self {
        DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(timestamp.sec, timestamp.nsec as u32),
            Utc,
        )
    }
}

impl From<RegistrationTimestamp> for DateTime<Utc> {
    fn from(timestamp: RegistrationTimestamp) -> Self {
        <&RegistrationTimestamp as Into<DateTime<Utc>>>::into(&timestamp)
    }
}

// However, DateTime uses differently sized sec and nsec nums, so we need to do very careful
// conversion between the two
impl TryFrom<DateTime<Utc>> for RegistrationTimestamp {
    type Error = TryFromIntError;

    fn try_from(timestamp: DateTime<Utc>) -> Result<Self, Self::Error> {
        Ok(Self {
            sec: timestamp.timestamp(),
            nsec: timestamp.timestamp_subsec_nanos().try_into()?,
        })
    }
}

/// User represents a user of any one of the swaply products. A user may be
/// authenticated with swaply itself, or with one of the supported
/// authentication providers.
#[derive(Serialize, Deserialize, Debug)]
pub struct User<'a> {
    /// The ID of the user - this field may never be omitted, as the server
    /// must generate a UID for the user.
    id: Uuid,

    /// The username associated with this user - this field may not be omitted
    /// safely.
    username: &'a str,

    /// The email associated with this user - this field may not be omitted
    /// safely.
    email: &'a str,

    /// A hash of this user's password, if they are registered through the
    /// traditional password-based registration service. Typically, such hashes
    /// are generated by passing a password with a prepended salt to the blake3
    /// hashing function.
    #[serde(with = "serde_bytes")]
    password_hash: &'a [u8],

    /// The time at which this user was registered.
    registered_at: RegistrationTimestamp,
}

impl<'a> User<'a> {
    /// Creates a new instance of the user details struct.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the user: if unassigned, a random UUID will be generated
    /// * `username` - The username associated with the user
    /// * `email` - The email associated with the user
    /// * `password_hash` - The hash of the user's password
    /// * `registered_at` - The time that the user registered with swaply: if left unassigned, the
    /// current UTC time will be used
    ///
    /// # Examples
    ///
    /// ```
    /// use swaply_identity::schema::user::User;
    /// use std::collections::HashMap;
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let u = User::new(None, "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), None);
    /// ```
    pub fn new(
        id: Option<Uuid>,
        username: &'a str,
        email: &'a str,
        password_hash: &'a [u8; 32],
        registered_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id: id.unwrap_or_else(Uuid::new_v4),
            username,
            email,
            password_hash,
            registered_at: registered_at
                .map(|timestamp| timestamp.try_into().unwrap_or_default())
                .unwrap_or_else(|| {
                    Utc::now()
                        .try_into()
                        .unwrap_or(RegistrationTimestamp::default())
                }),
        }
    }

    /// Gets the ID of the Swaply user.
    ///
    /// # Examples
    ///
    /// ```
    /// use swaply_identity::schema::user::User;
    /// use std::collections::HashMap;
    /// use uuid::Uuid;
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let id = Uuid::new_v4();
    /// let u = User::new(Some(id), "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), None);
    /// assert_eq!(u.id(), &id);
    /// ```
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Gets the username of the Swaply user.
    ///
    /// # Examples
    ///
    /// ```
    /// use swaply_identity::schema::user::User;
    /// use std::collections::HashMap;
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let u = User::new(None, "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), None);
    /// assert_eq!(u.username(), "test");
    /// ```
    pub fn username(&self) -> &str {
        self.username
    }

    /// Gets the email of the Swaply user.
    ///
    /// # Examples
    ///
    /// ```
    /// use swaply_identity::schema::user::User;
    /// use std::collections::HashMap;
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let u = User::new(None, "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), None);
    /// assert_eq!(u.email(), "test@test.com");
    /// ```
    pub fn email(&self) -> &str {
        self.email
    }

    /// Obtains a hash of the user's password, if they have registered via the traditional password
    /// authentication system.
    ///
    /// # Examples
    ///
    /// ```
    /// use swaply_identity::schema::user::{User, IdentityProvider};
    /// use std::collections::HashMap;
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let u = User::new(None, "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), None);
    /// assert_eq!(u.password_hash(), password_hash.as_bytes());
    /// ```
    pub fn password_hash(&self) -> &[u8; 32] {
        array_ref![self.password_hash, 0, 32]
    }

    /// Gets a timestamp matching the time at which the user registered with the swaply identity
    /// service.
    ///
    /// # Examples
    ///
    /// ```
    /// ```
    pub fn registered_at(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(self.registered_at.sec, self.registered_at.nsec as u32),
            Utc,
        )
    }
}

#[async_trait]
impl<'a> InTable for User<'a> {
    const KEYSPACE: &'static str = "identity";
    const TABLE: &'static str = "users";
    const COLUMNS: &'static str = "(id, username, email, identities, password_hash, registered_at)";

    async fn create_tables(session: &mut DbSession) -> IdentityResult<()> {
        futures_util::future::try_join3(
            session.query(
                // A table storing all users
                r#"
            CREATE TABLE IF NOT EXISTS identity.users (
                id UUID,
                username TEXT,
                email TEXT,
                password_hash TEXT,
                registered_at TIMESTAMP,
                PRIMARY KEY id
            );
        "#,
            ),
            session.query(
                // A table storing UUIDs for each registered nickname
                r#"
            CREATE TABLE IF NOT EXISTS identity.nicknames (
                user_id UUID,
                nickname TEXT,
                PRIMARY KEY nickname
            );
        "#,
            ),
            session.query(
                // A table storing UUIDs for each registered 3rd party identity
                r#"
            CREATE TABLE IF NOT EXISTS identity.user_connections (
                user_id UUID,
                connection_provider TEXT,
                id_for_provider TEXT,
                PRIMARY KEY (connection_provider, id_for_provider)
            );
        "#,
            ),
        )
        .await
        .map_err(|e| <TableError as Into<IdentityError>>::into(TableError::CDRSError(e)))
        .map(|_| ())
    }
}

impl Serializable<QueryValues> for User<'_> {
    type Error =  ConvertUserToQueryValuesError;

    fn try_into(&self) -> Result<QueryValues, Self::Error> {
        Ok(query_values!(
            "id" => u.id,
            "username" => u.username,
            "email" => u.email,
            "password_hash" => bs58::encode(u.password_hash.to_vec()).into_string(),
            "registered_at" => <&RegistrationTimestamp as Into<Timespec>>::into(&u.registered_at)
        ))
    }
}

#[derive(Debug)]
pub enum ConvertUserToQueryValuesError {
    SerializationError(BincodeError),
    EncodingError(bs58::encode::Error),
}

impl From<BincodeError> for ConvertUserToQueryValuesError {
    fn from(e: BincodeError) -> Self {
        Self::SerializationError(e)
    }
}

impl From<Bs58EncodingError> for ConvertUserToQueryValuesError {
    fn from(e: Bs58EncodingError) -> Self {
        Self::EncodingError(e)
    }
}

impl From<ConvertUserToQueryValuesError> for QueryError {
    fn from(e: ConvertUserToQueryValuesError) -> Self {
        QueryError::ParameterizationError(e)
    }
}

impl fmt::Display for ConvertUserToQueryValuesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "encountered an error while {}: {:?}",
            match self {
                Self::SerializationError(_) => "serializing the user: {}",
                Self::EncodingError(_) => "encoding the serialized user to base58: {}",
            },
            self.source().map(|e| e.to_string())
        )
    }
}

impl Error for ConvertUserToQueryValuesError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SerializationError(e) => Some(e),
            Self::EncodingError(e) => Some(e),
        }
    }
}

impl TryFrom<User<'_>> for QueryValues {
    type Error = ConvertUserToQueryValuesError;

    fn try_from(u: User) -> Result<Self, Self::Error> {
        Ok(query_values!(
            "id" => u.id,
            "username" => u.username,
            "email" => u.email,
            "password_hash" => bs58::encode(u.password_hash.to_vec()).into_string(),
            "registered_at" => <&RegistrationTimestamp as Into<Timespec>>::into(&u.registered_at)
        ))
    }
}

impl<'a> From<&'a OwnedUser> for User<'a> {
    fn from(u: &'a OwnedUser) -> Self {
        Self {
            id: u.id,
            username: u.username.as_ref(),
            email: u.email.as_ref(),
            password_hash: array_ref![u.password_hash.as_slice(), 0, 32],
            registered_at: u.registered_at,
        }
    }
}

/// UserQuery represents all non-filter queries for users.
#[derive(Debug)]
pub enum UserQuery<'a> {
    Id(Uuid),
    Nickname(&'a str),
}

#[async_trait]
impl Queryable<Scylla, DbSession> for UserQuery<'_> {
    async fn to_query(&self, session: &DbSession) -> IdentityResult<String> {
        let query_id = match self {
            Self::Id(id) => *id,
            Self::Nickname(nick) => session
                .query(format!(
                    "SELECT user_id FROM identity.nicknames WHERE nickname = '{}';",
                    nick,
                ))
                .await
                .and_then(|frame| frame.get_body())
                .map_err(|e| QueryError::CDRSError(e))
                .and_then(|body| body.into_rows().ok_or(QueryError::NoResults))
                .and_then(|mut rows| {
                    if rows.len() == 0 {
                        Err(QueryError::NoResults)
                    } else {
                        Ok(rows.remove(0))
                    }
                })
                .and_then(|row| {
                    <Row as IntoRustByName<Uuid>>::get_r_by_name(&row, "user_id")
                        .map_err(|e| <CDRSError as Into<QueryError>>::into(e))
                })?,
        };

        Ok(format!(
            "SELECT * FROM identity.users WHERE id = {}",
            query_id
        ))
    }
}

/// OwnedUser represents an allocated user.
#[derive(Debug)]
pub struct OwnedUser {
    id: Uuid,
    username: String,
    email: String,
    password_hash: Vec<u8>,
    registered_at: RegistrationTimestamp,
}

impl TryFromRow for OwnedUser {
    fn try_from_row(row: Row) -> CDRSResult<Self> {
        Ok(OwnedUser {
            id: row.get_r_by_index(0)?,
            username: row.get_r_by_index(1)?,
            email: row.get_r_by_index(2)?,
            password_hash: <Row as IntoRustByIndex<Blob>>::get_r_by_index(&row, 3)?.into_vec(),
            registered_at: <Timespec as Into<RegistrationTimestamp>>::into(row.get_r_by_index(4)?),
        })
    }
}

#[cfg(test)]
mod test {
    use cdrs::{
        authenticators::StaticPasswordAuthenticator,
        cluster::{ClusterTcpConfig, NodeTcpConfigBuilder},
        load_balancing::RoundRobin,
    };
    use chrono::{DateTime, Utc};
    use std::{collections::HashMap, env, error::Error};

    use super::{
        super::super::{db::Provider, error::IdentityError},
        *,
    };

    #[tokio::test]
    async fn test_load_user() -> Result<(), Box<dyn Error>> {
        let password_hash = blake3::hash(b"123456");
        let u = User::new(
            None,
            "test",
            "test@test.com",
            password_hash.as_bytes(),
            None,
        );

        let db_node = env::var("SCYLLA_NODE_URL")?;

        let auth = StaticPasswordAuthenticator::new(
            env::var("SCYLLA_USERNAME")?,
            env::var("SCYLLA_PASSWORD")?,
        );
        let node = NodeTcpConfigBuilder::new(&db_node, auth).build();
        let cluster_config = ClusterTcpConfig(vec![node]);
        let mut session = cdrs::cluster::session::new(&cluster_config, RoundRobin::new()).await?;

        super::super::super::create_keyspace(&mut session).await?;

        let db = Scylla::new(session);
        db.insert_record(u).await?;

        Ok(())
    }
}
