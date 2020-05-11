/// IdentityProvider represents any arbitrary provider of an authorization or
/// authentication service (i.e., a provider of an OpenID Connection-capable
/// identity API).
pub enum IdentityProvider {
    /// Google provides an OpenID connect OAuth 2.0 API: https://developers.google.com/identity/protocols/oauth2/openid-connect
    Google,

    /// GitHub also provides an OAuth 2.0 API, but uses non-standard endpoints: https://fusionauth.io/docs/v1/tech/identity-providers/openid-connect/github
    /// Also, their docs are pretty unclear, which doesn't help.
    GitHub,

    /// Twitch has excellent OpenID connect integration: https://dev.twitch.tv/docs/authentication/getting-tokens-oidc
    Twitch,

    /// 
    Reddit,
    Twitter,
    Discord,
}

pub struct User<'a> {
    id: u64,

    username: &'a str,
}
