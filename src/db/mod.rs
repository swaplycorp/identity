use super::{error::QueryError, result::IdentityResult};

pub mod scylla;

/// Provider represents any provider of long-term user information (e.g., redis, scylla).
#[async_trait]
pub trait Provider<DB, Session> {
    /// NativeType is any struct that serves as a medium between the initial record type and the
    /// raw, native database type (e.g., Scylla rows).
    type ResponseIntermediary;

    /// RequestIntermediary is any struct that serves as a medium in conversion from the initial
    /// record type to the raw, native database type (e.g., Scylla QueryValues).
    type RequestIntermediary;

    /// Loads a database record into a struct instance.
    ///
    /// # Arguments
    ///
    /// * `q` - The query that shoul be executed on the provider.
    async fn load_record<
        K: Queryable<DB, Session> + Send + Sync,
        V: Deserializable<Self::ResponseIntermediary> + Send,
    >(
        &self,
        q: K,
    ) -> IdentityResult<V>;

    /// Inserts a new record into the database.
    ///
    /// # Arguments
    ///
    /// * `r` - The record that should be inserted into the database
    async fn insert_record<V: Serializable<Self::RequestIntermediary> + Insertable<DB> + Send + Sync>(
        &self,
        r: V,
    ) -> IdentityResult<()>;
}

/// Queryable represents a type that implements a query generator for the respective database
/// provider.
#[async_trait]
pub trait Queryable<DB, Session> {
    /// Constructs a query from the query type.
    async fn to_query(&self, session: &Session) -> IdentityResult<String>;
}

/// Insertable represents a type that implements an insertion query generator for the respective
/// database provider.
pub trait Insertable<DB> {
    /// Constructs a query from the query type.
    fn to_insertion_query(&self) -> IdentityResult<String>;
}

/// Deserializable represents a type that may be converted to from a NativeType defined by a
/// Provider.
pub trait Deserializable<T>: Sized {
    type Error: Into<QueryError>;

    /// Converts the NativeType to the desired type.
    ///
    /// # Arguments
    ///
    /// * `value` - The native type instance
    fn try_from(value: T) -> Result<Self, Self::Error>;
}

//// Serializable represents a type that may be converted to a NativeType defined by a Provider.
pub trait Serializable<T> {
    type Error: Into<QueryError> + Send;

    /// Converts the Rust type to a native type.
    fn try_into(&self) -> Result<T, Self::Error>;
}
