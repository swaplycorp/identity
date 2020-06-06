use super::result::IdentityResult;

pub mod scylla;

/// Provider represents any provider of long-term user information (e.g., redis, scylla).
#[async_trait]
pub trait Provider {
    /// QueryType represents the only accepted query type for queries done on this provider.
    type QueryType;

    /// Loads a database record into a struct instance.
    ///
    /// # Arguments
    ///
    /// * `q` - The value that should be queried for in the database
    async fn load_record<T>(&self, q: Self::QueryType) -> IdentityResult<T>;

    /// Inserts a new record into the database.
    ///
    /// # Arguments
    ///
    /// * `r` - The record that should be inserted into the database
    async fn insert_record<T>(&self, r: T) -> IdentityResult<()>;
}

/// Queryable represents a type that implements conversion to a query for the respective provider.
pub trait Queryable<DB> {
    /// Constructs a query from the query type.
    fn to_query(&self) -> String;
}
