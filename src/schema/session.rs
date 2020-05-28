use chrono::Duration;
use uuid::Uuid;

/// Sessions will be kept alive for one month, unless explicitly terminated by the user.
const SessionKeepAlive: Duration = Duration::days(31);

/// Session represents a login session for an individual user, for which many sessions may be made.
pub struct Session {
    /// The user to whom the session belongs.
   user_id: Uuid, 
}
