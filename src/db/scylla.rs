use cdrs::{
    error::Error as CDRSError,
    query::{QueryExecutor, QueryValues},
    types::rows::Row,
};

use super::{
    super::{error::QueryError, result::IdentityResult, DbSession},
    Deserializable, Insertable, Provider, Queryable, Serializable,
};

/// InTable represents any type that may be stored in a keyspace and table.
#[async_trait]
pub trait InTable {
    /// The keyspace that the struct should be stored in.
    const KEYSPACE: &'static str;

    /// The table that the struct should be stored in.
    const TABLE: &'static str;

    /// The columns contained in the struct represented in the following form: "(column1, colum2,
    /// etc...)"
    const COLUMNS: &'static str;

    /// Creates any associated tables necessary for operation.
    ///
    /// # Arguments
    ///
    /// * `session` - The database connector that should be used to create the table
    async fn create_tables(session: &mut DbSession) -> IdentityResult<()>;
}

/// Scylla represents a connector capable of loading and inserting struct data via scylladb.
#[derive(Debug)]
pub struct Scylla {
    session: DbSession,
}

impl Scylla {
    /// Creates a new instance of the scylla connector with the given session.
    ///
    /// # Arguments
    ///
    /// * `session` - The database session that should be used for database operation
    pub fn new(session: DbSession) -> Self {
        Self { session }
    }
}

// Providers may only be implemented for types that:
// 1. Are queryable by types that implement a to_query method themselves
// 2. Can be converted into a cdrs row
// 3. Can be converted into a CDRS QueryValues instance
// 4. Specify the names of their keyspace, table, and columns
// 5. Return an error that can be converted into an IdentityError when converting the initial
//    struct into a CDRS QueryValues instance
// 6. Implement conversion from a database row to a struct instance.
//
// NOTE: Two types may be used for storage and for insertion. As such, load_record and
// insert_record refer to different kinds of values, with lesser and greater constraints.
#[async_trait]
impl Provider<Self, DbSession> for Scylla {
    type ResponseIntermediary = Row;
    type RequestIntermediary = QueryValues;

    async fn load_record<
        K: Queryable<Self, DbSession> + Send + Sync,
        V: Deserializable<Self::ResponseIntermediary> + Send,
    >(
        &self,
        q: K,
    ) -> IdentityResult<V> {
        self.session
            // Allow the struct impelemting conversion to construct a query
            .query(q.to_query(&self.session).await?)
            .await
            // Convert generalized results into a set of rows
            .and_then(|frame| frame.get_body())
            .map_err(|e| e.into())
            // Ensure that some rows have been returned
            .and_then(|resp| resp.into_rows().ok_or(QueryError::NoResults))
            .and_then(|mut rows| {
                if rows.len() == 0 {
                    Err(QueryError::NoResults)
                } else {
                    Ok(rows.remove(0))
                }
            })
            // Convert any existent rows to the struct in question
            .and_then(|row| V::try_from(row).map_err(|e| e.into()))
            // Convert QueryError to a generalized Error type
            .map_err(|e| e.into())
    }

    /// Inserts a struct into the scylla database via the working session. Insertion is
    /// automatically supported for structs that:
    /// - Implement conversion into a CDRS QueryValues instance
    /// - Return an Error type that may be converted into an IdentityError upon such conversion
    /// - Specify an insertion query template via an implementation of Insertable<DB>
    async fn insert_record<
        V: Serializable<Self::RequestIntermediary> + Insertable<Scylla> + Send + Sync,
    >(
        &self,
        r: V,
    ) -> IdentityResult<()> {
        self.session
            .query_with_values(
                r.to_insertion_query()?,
                // The struct being inserted must return a type that can be converted to an
                // IdentityError when the struct is converted to a QueryValues instance. As such,
                // we can convert the error that the struct returns upon conversion to the desired
                // generalized IdentityError type. Furthermore, we can use ? to simply pass the
                // result up
                <V as Serializable<QueryValues>>::try_into(&r).map_err(|e| e.into())?,
            )
            .await
            .map(|_| ())
            .map_err(|e| <CDRSError as Into<QueryError>>::into(e).into())
    }
}
