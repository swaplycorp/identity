use super::super::{db::{InTable, scylla::Scylla}, error::TableError, DbSession, IdentityResult};

use cdrs::query::QueryExecutor;

use uuid::Uuid;

/// NicknameRecord represents an owned copy of a mapping between a nickname and a UUID.
#[derive(Debug)]
pub struct NicknameRecord {
    id: Uuid,

    nickname: String,
}

impl NicknameRecord {
    /// Obtains the Uuid of the user in question.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Obtains the username of the user in question.
    pub fn nickname(&self) -> &str {
        self.nickname.as_ref()
    }
}

#[async_trait]
impl InTable<Scylla, DbSession> for NicknameRecord {
    async fn create_prerequisite_objects(session: &DbSession) -> IdentityResult<()> {
        session
            .query(
                r#"
                    CREATE TABLE IF NOT EXISTS identity.nicknames (
                        user_id UUID,
                        nickname TEXT,
                        PRIMARY KEY nickname
                    );
                "#,
            )
            .await
            .map_err(|e| TableError::CDRSError(e).into())
            .map(|_| ())
    }
}
