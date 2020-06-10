use super::{error::QueryError, result::IdentityResult};

pub mod scylla;

/// Provider represents any provider of long-term user information (e.g., redis, scylla).
#[async_trait]
pub trait Provider<Db, Session> {
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
    /// * `q` - The query that should be executed on the provider.
    async fn load_record<
        K: Queryable<Db, Session> + Send + Sync,
        V: Deserializable<V, Self::ResponseIntermediary> + Send,
    >(
        &self,
        q: K,
    ) -> IdentityResult<V>;

    /// Inserts a new record into the database.
    ///
    /// # Arguments
    ///
    /// * `r` - The record that should be inserted into the database
    async fn insert_record<V: Serializable<Self::RequestIntermediary> + Insertable<Db, Session> + Send + Sync>(
        &self,
        r: V,
    ) -> IdentityResult<()>;
}

/// Queryable represents a type that implements a query generator for the respective database
/// provider.
#[async_trait]
pub trait Queryable<Db, Session> {
    /// Constructs a query from the query type.
    async fn to_query(&self, session: &Session) -> IdentityResult<String>;
}

/// Insertable represents a type that implements an insertion query generator for the respective
/// database provider.
pub trait Insertable<Db, Session> {
    /// Constructs a query from the query type.
    fn to_insertion_query(&self) -> IdentityResult<&str>;
}

/// Deserializable represents a type that may be converted to from a NativeType defined by a
/// Provider.
pub trait Deserializable<ComplexType, DbType> {
    type Error: Into<QueryError>;

    /// Converts the NativeType to the desired type.
    ///
    /// # Arguments
    ///
    /// * `value` - The native type instance
    fn try_from(value: DbType) -> Result<ComplexType, Self::Error>;
}

//// Serializable represents a type that may be converted to a NativeType defined by a Provider.
pub trait Serializable<DbType> {
    type Error: Into<QueryError> + Send;

    /// Converts the Rust type to a native type.
    fn try_into(&self) -> Result<DbType, Self::Error>;
}

/// InTable represents a struct that can be represented as a record in a relational or SQL-like
/// table.
#[async_trait]
pub trait InTable<Db, Session> {
    /// Creates any keyspaces or tables necessary for the proper usage of the struct that may be
    /// rperesented in a database.
    async fn create_prerequisite_objects(session: &Session) -> IdentityResult<()>;
}
