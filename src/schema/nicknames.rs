use super::{super::{DbSession, result::Result as IdentityResult}, user::OwnedUser};

/// Obtains 
pub async fn lookup_from_table(session: &mut DbSession, username: &str) -> IdentityResult<OwnedUser> {

}
