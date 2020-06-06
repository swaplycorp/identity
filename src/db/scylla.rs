use cdrs::{
    error::Error as CDRSError,
    frame::traits::TryFromRow,
    query::{QueryExecutor, QueryValues},
};
use regex::Regex;

use super::{
    super::{
        error::{Error as IdentityError, InsertionError, QueryError},
        result::IdentityResult,
        DbSession,
    },
    Provider, Queryable,
};

use std::convert::TryInto;

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
    async fn create_tables(session: &mut DbSession) -> IdentityResult<()>;
}

/// Scylla represents a connector capable of loading and inserting struct data via scylladb.
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
impl<K: Queryable<Self>> Provider for Scylla {
    type QueryType = K;

    async fn load_record<V: TryFromRow>(&self, q: K) -> IdentityResult<V> {
        self.session
            // Allow the struct impelemting conversion to construct a query
            .query(q.to_query())
            .await
            // Convert generalized results into a set of rows
            .and_then(|frame| frame.get_body())
            .map_err(|e| e.into())
            // Ensure that some rows have been returned
            .and_then(|resp| resp.into_rows().ok_or(QueryError::NoResults))
            .and_then(|rows| rows.get(0).ok_or(QueryError::NoResults))
            // Convert any existent rows to the struct in question
            .and_then(|row| V::try_from_row(*row).map_err(|e| e.into()))
            // Convert QueryError to a generalized Error type
            .map_err(|e| e.into())
    }

    /// Inserts a struct into the scylla database via the working session. Insertion is
    /// automatically supported for structs that:
    /// - Implement conversion into a CDRS QueryValues instance
    /// - Return an Error type that may be converted into an IdentityError upon such conversion
    /// - Specify their keyspace, table, and columns via an implementation of InTable
    async fn insert_record<V: TryInto<QueryValues> + InTable>(&self, v: V) -> IdentityResult<()>
    where
        <V as TryInto<QueryValues>>::Error: Into<IdentityError>,
    {
        self.session
            .query_with_values(
                // Formulate a query that inserts the given struct into its:
                // 1. Keyspace and table indicated by its InTable implementation
                // 2. With its columns and values indicated by its aforementioned implementation of
                //    such a trait
                format!(
                    r#"INSERT INTO {}.{} ({}) VALUES ({});"#,
                    V::KEYSPACE,
                    V::TABLE,
                    V::COLUMNS,
                    // Replace all column names with ? marks, since we'll entrust CDRS with
                    // converting the respective values for us
                    Regex::new(r#"[^\(\), ]"#)
                        .map_err(|e| <InsertionError as Into<IdentityError>>::into(
                            InsertionError::RegexError(e)
                        ))?
                        .replace_all(V::COLUMNS, "?")
                ),
                // The struct being inserted must return a type that can be converted to an
                // IdentityError when the struct is converted to a QueryValues instance. As such,
                // we can convert the error that the struct returns upon conversion to the desired
                // generalized IdentityError type. Furthermore, we can use ? to simply pass the
                // result up
                <V as TryInto<QueryValues>>::try_into(v).map_err(|e| e.into())?,
            )
            .await
            .map(|_| ())
            .map_err(|e| <CDRSError as Into<QueryError>>::into(e).into())
    }
}
