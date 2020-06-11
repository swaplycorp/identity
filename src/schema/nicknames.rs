use super::super::{
    db::{scylla::Scylla, InTable},
    error::IdentityError,
    result::IdentityResult,
    DbSession,
};

use cdrs::{error::Error as CDRSError, query::QueryExecutor};
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
            .map_err(|e| <CDRSError as Into<IdentityError>>::into(e))
            .map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use cdrs::{
        authenticators::StaticPasswordAuthenticator,
        cluster::{ClusterTcpConfig, NodeTcpConfigBuilder},
        load_balancing::RoundRobin,
    };
    use std::{env, error::Error};

    use super::{
        super::{super::db::Provider, user},
        *,
    };
    use crate::testing;

    #[tokio::test]
    async fn test_insert_nickname_record() -> Result<(), Box<dyn Error>> {
        let session = testing::open_session().await?;

        Ok(())
    }
}
