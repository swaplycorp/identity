use bincode::Error as BincodeError;
use bs58::encode::Error as Bs58EncodingError;
use cdrs::{
    error,
    frame::traits::TryFromRow,
    query::{QueryExecutor, QueryValues},
    query_values,
    types::{blob::Blob, map::Map, prelude::Row, value::Bytes, AsRustType, IntoRustByIndex},
    Result as CDRSResult,
};
use chrono::{naive::NaiveDateTime, DateTime, Utc};
use serde::{
    Deserialize, Serialize,
};
use time::Timespec;
use uuid::Uuid;

use super::super::DbSession;

use std::{
    collections::HashMap,
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
        Self{
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

// NOTE: We don't implement direct conversion from the RegistrationTimestamp type to rows
// themselves, since we use Timespec as an intermediary type that does implement such features

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

    /// Each of the third party identity providers that the user chosen to
    /// connect to their account.
    identities: HashMap<IdentityProvider, &'a str>,

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
    /// * `identities` - Each of the user's "connections" with third party ID providers
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
        identities: HashMap<IdentityProvider, &'a str>,
        password_hash: &'a [u8; 32],
        registered_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id: id.unwrap_or_else(Uuid::new_v4),
            username,
            email,
            identities,
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

    /// Obtains a reference to the set of third party identity integrations associated with this
    /// user.
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
    /// assert_eq!(*u.identities(), HashMap::new());
    /// ```
    pub fn identities(&self) -> &HashMap<IdentityProvider, &str> {
        &self.identities
    }

    /// Obtains the user ID associated with one of a user's connections.
    ///
    /// # Arguments
    ///
    /// * `provider` - The identity provider for which a user ID should be obtained
    ///
    /// # Examples
    ///
    /// ```
    /// use swaply_identity::schema::user::{User, IdentityProvider};
    /// use uuid::Uuid;
    /// use std::collections::HashMap;
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let mut identities = HashMap::new();
    /// identities.insert(IdentityProvider::GitHub, "dowlandaiello");
    ///
    /// let u = User::new(None, "test", "test@test.com", identities, password_hash.as_bytes(), None);
    ///
    /// assert_eq!(u.user_id_for(IdentityProvider::GitHub), Some("dowlandaiello"));
    /// ```
    pub fn user_id_for(&self, provider: IdentityProvider) -> Option<&str> {
        self.identities.get(&provider).map(|s| *s)
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
    /// use swaply_identity::schema::user::{User, IdentityProvider};
    /// use std::collections::HashMap;
    /// use chrono::{Utc, DateTime};
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let registered_at = Utc::now();
    /// let mut u = User::new(None, "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), Some(registered_at));
    /// assert_eq!(u.registered_at(), registered_at);
    ///
    /// u = User::new(None, "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), None);
    /// u.registered_at(); // An ISO 8601 timestamp representing the time at which u was created
    /// ```
    pub fn registered_at(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(self.registered_at.sec, self.registered_at.nsec as u32),
            Utc,
        )
    }

    /// Inserts the user into the database indicated by the given session.
    ///
    /// # Arguments
    ///
    /// * `session` - The syclla db connector that should be used
    ///
    /// # Examples
    ///
    /// ```
    /// use cdrs::{authenticators::StaticPasswordAuthenticator, cluster::{NodeTcpConfigBuilder, ClusterTcpConfig}, load_balancing::RoundRobin};
    /// use std::{env, error::Error, collections::HashMap};
    /// use swaply_identity::schema::user::User;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn Error>> {
    /// # dotenv::dotenv()?;
    ///
    /// let db_node = env::var("SCYLLA_NODE_URL")?;
    ///
    /// let auth = StaticPasswordAuthenticator::new(env::var("SCYLLA_USERNAME")?, env::var("SCYLLA_PASSWORD")?);
    /// let node = NodeTcpConfigBuilder::new(&db_node, auth).build();
    /// let cluster_config = ClusterTcpConfig(vec![node]);
    /// let mut session = cdrs::cluster::session::new(&cluster_config, RoundRobin::new()).await?;
    ///
    /// swaply_identity::create_keyspace(&mut session).await?;
    /// swaply_identity::schema::user::create_tables(&mut session).await?;
    ///
    /// let password_hash = blake3::hash(b"123456");
    ///
    /// let u = User::new(None, "test", "test@test.com", HashMap::new(), password_hash.as_bytes(), None);
    /// u.insert_into_table(&mut session).await?;
    ///
    /// Ok(())
    /// # }
    /// ```
    pub async fn insert_into_table(self, session: &mut DbSession) -> CDRSResult<()> {
        session.query_with_values(r#"
            INSERT INTO identity.users (id, username, email, identities, password_hash, registered_at)
                VALUES (?, ?, ?, ?, ?, ?);
        "#, <Self as TryInto<QueryValues>>::try_into(self).map_err(|e| e.to_string())?).await.map(|_| ())
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
            "identities" => u.identities,
            "password_hash" => bs58::encode(u.password_hash.to_vec()).into_string(),
            "registered_at" => <&RegistrationTimestamp as Into<Timespec>>::into(&u.registered_at)
        ))
    }
}

impl<'a> From<&'a OwnedUser> for User<'a> {
    fn from(u: &'a OwnedUser) -> Self {
        // We're going to try to reference data from an OwnedUser
        let mut identities_ref: HashMap<IdentityProvider, &'a str> = HashMap::new();
        u.identities
            .0
            .keys()
            .into_iter()
            .zip(u.identities.0.values().into_iter())
            .map(|(key, value)| identities_ref.insert(*key, value))
            .for_each(drop);

        Self {
            id: u.id,
            username: u.username.as_ref(),
            email: u.email.as_ref(),
            identities: identities_ref,
            password_hash: array_ref![u.password_hash.as_slice(), 0, 32],
            registered_at: u.registered_at,
        }
    }
}

/// IdentityMap represents any arbitrary number of mappings between identity providers and their
/// respective identity values (e.g., id numbers / JWTs).
#[derive(Debug)]
struct IdentityMap(HashMap<IdentityProvider, String>);

impl AsRustType<IdentityMap> for Map {
    fn as_rust_type(&self) -> CDRSResult<Option<IdentityMap>> {
        let identities: HashMap<String, String> =
            <Self as AsRustType<HashMap<String, String>>>::as_rust_type(self)?
                .ok_or(error::column_is_empty_err("identities"))?;

        // Now, we're going to move all of the values from the identities hashmap to the
        // fixed_identities hashmap, after converting each of the keys to IdentityProviders
        let mut fixed_identities: IdentityMap = IdentityMap(HashMap::new());
        identities
            .into_iter()
            .map(|(key, value)| {
                key.try_into()
                    .map(|key| fixed_identities.0.insert(key, value))
            })
            .filter_map(Result::ok)
            .for_each(drop);

        Ok(Some(fixed_identities))
    }
}

/// OwnedUser represents an allocated user.
#[derive(Debug)]
pub struct OwnedUser {
    id: Uuid,
    username: String,
    email: String,
    identities: IdentityMap,
    password_hash: Vec<u8>,
    registered_at: RegistrationTimestamp,
}

impl TryFromRow for OwnedUser {
    fn try_from_row(row: Row) -> CDRSResult<Self> {
        Ok(OwnedUser {
            id: row.get_r_by_index(0)?,
            username: row.get_r_by_index(1)?,
            email: row.get_r_by_index(2)?,
            identities: <Row as IntoRustByIndex<Map>>::get_r_by_index(&row, 3)?
                .as_rust_type()?
                .ok_or(error::column_is_empty_err(3))?,
            password_hash: <Row as IntoRustByIndex<Blob>>::get_r_by_index(&row, 4)?.into_vec(),
            registered_at: <Timespec as Into<RegistrationTimestamp>>::into(row.get_r_by_index(5)?),
        })
    }
}

/// Creates the necessary keyspace to store users.
///
/// # Arguments
///
/// * `session` - The syclla db connector that should be used
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
/// let auth = StaticPasswordAuthenticator::new(env::var("SCYLLA_USERNAME")?, env::var("SCYLLA_PASSWORD")?);
/// let node = NodeTcpConfigBuilder::new(&db_node, auth).build();
/// let cluster_config = ClusterTcpConfig(vec![node]);
/// let mut session = cdrs::cluster::session::new(&cluster_config, RoundRobin::new()).await?;
///
/// swaply_identity::create_keyspace(&mut session).await?;
/// swaply_identity::schema::user::create_tables(&mut session).await?;
///
/// Ok(())
/// # }
/// ```
pub async fn create_tables(session: &mut DbSession) -> CDRSResult<()> {
    futures_util::try_join!(
        session.query(
            r#"
            CREATE TABLE IF NOT EXISTS identity.users (
                id UUID,
                username TEXT,
                email TEXT,
                identities MAP<TEXT, TEXT>,
                password_hash TEXT,
                registered_at TIMESTAMP,
                PRIMARY KEY (id, username, email)
            );
        "#,
        ),
        session.query(
            r#"
                CREATE TABLE IF NOT EXISTS identity.user_connections (
                    user_id UUID,
                    connection_provider TEXT,
                    id_for_provider TEXT,
                    PRIMARY KEY ((user_id, connection_provider))
                );
            "#,
        )
    )
    .map(|_| ())
}
