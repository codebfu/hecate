//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::audit::append_audit;
use crate::crypto::{hash_password, verify_password};
use crate::error::{ApiError, ApiResult};
use crate::session::{self, OperatorSession};
use crate::state::AppState;

#[derive(Serialize)]
struct AuthStatus {
    bootstrap_required: bool,
    authenticated: bool,
    onboarding_required: bool,
    role: Option<String>,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    onboarding_required: bool,
    must_change_password: bool,
    auth_stage: Option<String>,
    role: Option<String>,
    login: Option<String>,
    csrf_token: Option<String>,
}

#[derive(Deserialize)]
struct BootstrapBody {
    login: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginBody {
    login: String,
    password: String,
}

#[derive(Deserialize)]
struct PasswordChangeBody {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct OnboardingPasswordBody {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct WebauthnRegisterFinishBody {
    credential: RegisterPublicKeyCredential,
    name: Option<String>,
}

#[derive(Deserialize)]
struct WebauthnAuthenticateFinishBody {
    credential: PublicKeyCredential,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/status", get(status))
        .route("/api/v1/auth/session", get(session))
        .route("/api/v1/auth/bootstrap", post(bootstrap))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/password/change", post(password_change))
        .route("/api/v1/auth/logout", post(logout))
        .route(
            "/api/v1/auth/onboarding/password",
            post(onboarding_password),
        )
        .route(
            "/api/v1/auth/onboarding/complete",
            post(onboarding_complete),
        )
        .route(
            "/api/v1/auth/webauthn/register/options",
            post(webauthn_register_options),
        )
        .route(
            "/api/v1/auth/webauthn/register/verify",
            post(webauthn_register_verify),
        )
        .route(
            "/api/v1/auth/webauthn/authenticate/options",
            post(webauthn_authenticate_options),
        )
        .route(
            "/api/v1/auth/webauthn/authenticate/verify",
            post(webauthn_authenticate_verify),
        )
}

async fn status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<AuthStatus>> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operators")
        .fetch_one(&state.pool)
        .await?;
    let operator = session::optional_session(&state, &jar).await?;
    let (authenticated, onboarding_required, role) = match operator {
        Some(op) => (
            true,
            !op.onboarding_complete,
            Some(op.role),
        ),
        None => (false, false, None),
    };
    Ok(Json(AuthStatus {
        bootstrap_required: count == 0,
        authenticated,
        onboarding_required,
        role,
    }))
}

async fn session(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Json<SessionResponse>)> {
    let Some(operator) = session::optional_session(&state, &jar).await? else {
        return Ok((jar, Json(unauthenticated_session())));
    };
    let csrf_token =
        session::rotate_csrf_token(&state.pool, &state.config, operator.session_id).await?;
    Ok((jar, Json(session_response(&operator, Some(csrf_token)))))
}

async fn bootstrap(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<BootstrapBody>,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    validate_login(&body.login)?;
    validate_password(&body.password)?;
    let hash = hash_password(&body.password).map_err(ApiError::Internal)?;
    let id = Uuid::new_v4();

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('hecate-bootstrap'))")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operators")
        .fetch_one(&mut *tx)
        .await?;
    if count > 0 {
        return Err(ApiError::Conflict("bootstrap already done".into()));
    }
    sqlx::query(
        "INSERT INTO operators (id, login, password_hash, role, must_change_password, onboarding_complete)
         VALUES ($1, $2, $3, 'admin', false, false)",
    )
    .bind(id)
    .bind(&body.login)
    .bind(&hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    append_audit(
        &state.pool,
        &body.login,
        "auth.bootstrap",
        &id.to_string(),
        "",
        &serde_json::json!({ "login": body.login }),
    )
    .await?;

    let (session_id, csrf_token) =
        session::create_session(&state.pool, &state.config, id, "password").await?;
    let jar = session::attach_session_cookie(jar, session_id, session::cookie_secure(&state.config));

    Ok((
        jar,
        Json(serde_json::json!({
            "authenticated": true,
            "operator_id": id,
            "login": body.login,
            "role": "admin",
            "onboarding_required": true,
            "csrf_token": csrf_token,
        })),
    ))
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginBody>,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let row: Option<(Uuid, String, String, bool, String, i32, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
        "SELECT id, password_hash, role::text, onboarding_complete, login, failed_login_count, locked_until
         FROM operators
         WHERE login = $1 AND disabled_at IS NULL",
    )
    .bind(&body.login)
    .fetch_optional(&state.pool)
    .await?;

    let Some((id, hash, role, onboarding, login, failed_login_count, locked_until)) = row else {
        return Err(ApiError::Unauthorized);
    };

    if let Some(until) = locked_until {
        if until > chrono::Utc::now() {
            return Err(ApiError::TooManyRequests(
                "account temporarily locked due to failed login attempts".into(),
            ));
        }
    }

    if !verify_password(&hash, &body.password) {
        let next_count = failed_login_count + 1;
        let lock_until = if should_lock_account_after_failure(failed_login_count) {
            Some(chrono::Utc::now() + chrono::Duration::minutes(15))
        } else {
            None
        };
        sqlx::query(
            "UPDATE operators SET failed_login_count = $1, locked_until = $2 WHERE id = $3",
        )
        .bind(next_count)
        .bind(lock_until)
        .bind(id)
        .execute(&state.pool)
        .await?;
        let _ = append_audit(
            &state.pool,
            &login,
            if lock_until.is_some() {
                "auth.login_locked"
            } else {
                "auth.login_failed"
            },
            &id.to_string(),
            "",
            &serde_json::json!({ "failed_login_count": next_count }),
        )
        .await;
        return Err(ApiError::Unauthorized);
    }

    sqlx::query(
        "UPDATE operators SET failed_login_count = 0, locked_until = NULL WHERE id = $1",
    )
    .bind(id)
    .execute(&state.pool)
    .await?;

    let (session_id, csrf_token) =
        session::create_session(&state.pool, &state.config, id, "password").await?;
    let jar = session::attach_session_cookie(jar, session_id, session::cookie_secure(&state.config));

    Ok((
        jar,
        Json(serde_json::json!({
            "authenticated": true,
            "operator_id": id,
            "login": login,
            "role": role,
            "onboarding_required": !onboarding,
            "auth_stage": "password",
            "csrf_token": csrf_token,
        })),
    ))
}

/// Verify the `X-CSRF-Token` header against the operator's active session.
/// Applied to every state-changing auth mutation, mirroring `admin_auth`'s CSRF
/// enforcement, but without requiring onboarding to already be complete (some of
/// these endpoints run mid-onboarding, before `ensure_onboarded` would pass).
async fn require_csrf(state: &AppState, session_id: Uuid, headers: &HeaderMap) -> ApiResult<()> {
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Forbidden)?;
    session::verify_csrf(&state.config, &state.pool, session_id, csrf).await
}

async fn password_change(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<PasswordChangeBody>,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let operator = session::require_session(&state, &jar).await?;
    require_csrf(&state, operator.session_id, &headers).await?;
    validate_password(&body.new_password)?;
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM operators WHERE id = $1")
        .bind(operator.operator_id)
        .fetch_one(&state.pool)
        .await?;
    if !verify_password(&hash, &body.current_password) {
        return Err(ApiError::Unauthorized);
    }
    let new_hash = hash_password(&body.new_password).map_err(ApiError::Internal)?;
    sqlx::query("UPDATE operators SET password_hash = $1 WHERE id = $2")
        .bind(new_hash)
        .bind(operator.operator_id)
        .execute(&state.pool)
        .await?;
    Ok((jar, Json(serde_json::json!({ "ok": true }))))
}

async fn onboarding_password(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<OnboardingPasswordBody>,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let operator = session::require_session(&state, &jar).await?;
    require_csrf(&state, operator.session_id, &headers).await?;
    validate_password(&body.new_password)?;

    let hash: String = sqlx::query_scalar("SELECT password_hash FROM operators WHERE id = $1")
        .bind(operator.operator_id)
        .fetch_one(&state.pool)
        .await?;
    if !verify_password(&hash, &body.current_password) {
        return Err(ApiError::Unauthorized);
    }

    let new_hash = hash_password(&body.new_password).map_err(ApiError::Internal)?;
    sqlx::query(
        "UPDATE operators SET password_hash = $1, must_change_password = false WHERE id = $2",
    )
    .bind(new_hash)
    .bind(operator.operator_id)
    .execute(&state.pool)
    .await?;

    Ok((jar, Json(serde_json::json!({ "ok": true }))))
}

async fn webauthn_register_options(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let operator = session::require_session(&state, &jar).await?;

    let exclude: Vec<CredentialID> = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT credential_id FROM operator_webauthn_credentials
         WHERE operator_id = $1 AND revoked_at IS NULL",
    )
    .bind(operator.operator_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(CredentialID::from)
    .collect();

    let (options, registration) = state
        .webauthn
        .start_passkey_registration(
            operator.operator_id,
            &operator.login,
            &operator.login,
            Some(exclude),
        )
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("webauthn options: {e}")))?;

    state
        .webauthn_challenges
        .insert(operator.operator_id, registration);

    Ok((
        jar,
        Json(
            serde_json::to_value(&options.public_key)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?,
        ),
    ))
}

async fn webauthn_register_verify(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<WebauthnRegisterFinishBody>,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let operator = session::require_session(&state, &jar).await?;
    require_csrf(&state, operator.session_id, &headers).await?;

    let registration = state
        .webauthn_challenges
        .remove(&operator.operator_id)
        .ok_or_else(|| ApiError::BadRequest("registration challenge expired".into()))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&body.credential, &registration)
        .map_err(|e| ApiError::BadRequest(format!("webauthn verify failed: {e}")))?;

    let credential_id = passkey.cred_id().to_vec();
    let public_key =
        serde_json::to_vec(&passkey).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    let name = body
        .name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "Primary passkey".to_string());

    sqlx::query(
        "INSERT INTO operator_webauthn_credentials (id, operator_id, name, credential_id, public_key)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(operator.operator_id)
    .bind(name)
    .bind(credential_id)
    .bind(public_key)
    .execute(&state.pool)
    .await?;

    Ok((jar, Json(serde_json::json!({ "ok": true }))))
}

async fn onboarding_complete(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let operator = session::require_session(&state, &jar).await?;
    require_csrf(&state, operator.session_id, &headers).await?;

    let credential_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operator_webauthn_credentials
         WHERE operator_id = $1 AND revoked_at IS NULL",
    )
    .bind(operator.operator_id)
    .fetch_one(&state.pool)
    .await?;
    if credential_count == 0 {
        return Err(ApiError::BadRequest(
            "register at least one WebAuthn passkey before completing onboarding".into(),
        ));
    }

    sqlx::query("UPDATE operators SET onboarding_complete = true WHERE id = $1")
        .bind(operator.operator_id)
        .execute(&state.pool)
        .await?;
    sqlx::query(
        "UPDATE operator_sessions SET auth_stage = 'full'::auth_stage WHERE session_id = $1",
    )
    .bind(operator.session_id)
    .execute(&state.pool)
    .await?;

    append_audit(
        &state.pool,
        &operator.login,
        "auth.onboarding.complete",
        &operator.operator_id.to_string(),
        "",
        &serde_json::json!({}),
    )
    .await?;

    Ok((jar, Json(serde_json::json!({ "ok": true }))))
}

async fn webauthn_authenticate_options(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let operator = session::require_session(&state, &jar).await?;
    if !operator.onboarding_complete {
        return Err(ApiError::BadRequest(
            "complete onboarding before WebAuthn sign-in".into(),
        ));
    }
    if operator.auth_stage == "full" {
        return Err(ApiError::BadRequest("session already fully authenticated".into()));
    }

    let rows: Vec<(Uuid, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT id, public_key, sign_count FROM operator_webauthn_credentials
         WHERE operator_id = $1 AND revoked_at IS NULL",
    )
    .bind(operator.operator_id)
    .fetch_all(&state.pool)
    .await?;

    if rows.is_empty() {
        return Err(ApiError::BadRequest(
            "no registered passkeys; contact an administrator".into(),
        ));
    }

    let mut passkeys = Vec::with_capacity(rows.len());
    for (_id, public_key, _sign_count) in rows {
        let passkey: Passkey = serde_json::from_slice(&public_key)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("invalid stored passkey: {e}")))?;
        passkeys.push(passkey);
    }

    let (options, authentication) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("webauthn auth options: {e}")))?;

    state
        .webauthn_auth_challenges
        .insert(operator.session_id, authentication);

    Ok((
        jar,
        Json(
            serde_json::to_value(&options.public_key)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?,
        ),
    ))
}

async fn webauthn_authenticate_verify(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<WebauthnAuthenticateFinishBody>,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let operator = session::require_session(&state, &jar).await?;
    require_csrf(&state, operator.session_id, &headers).await?;
    if !operator.onboarding_complete {
        return Err(ApiError::BadRequest(
            "complete onboarding before WebAuthn sign-in".into(),
        ));
    }
    if operator.auth_stage == "full" {
        return Err(ApiError::BadRequest("session already fully authenticated".into()));
    }

    let authentication = state
        .webauthn_auth_challenges
        .remove(&operator.session_id)
        .ok_or_else(|| ApiError::BadRequest("authentication challenge expired".into()))?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&body.credential, &authentication)
        .map_err(|e| ApiError::BadRequest(format!("webauthn authentication failed: {e}")))?;

    if !auth_result.user_verified() {
        return Err(ApiError::BadRequest(
            "passkey user verification required".into(),
        ));
    }

    let credential_id = auth_result.cred_id().to_vec();
    let row: Option<(Uuid, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT id, public_key, sign_count FROM operator_webauthn_credentials
         WHERE operator_id = $1 AND credential_id = $2 AND revoked_at IS NULL",
    )
    .bind(operator.operator_id)
    .bind(&credential_id)
    .fetch_optional(&state.pool)
    .await?;

    let (credential_row_id, public_key, sign_count) =
        row.ok_or_else(|| ApiError::BadRequest("unknown passkey credential".into()))?;

    let counter = auth_result.counter();
    if sign_count > 0 && counter <= sign_count as u32 {
        return Err(ApiError::BadRequest("passkey counter mismatch".into()));
    }

    let mut passkey: Passkey = serde_json::from_slice(&public_key)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("invalid stored passkey: {e}")))?;
    let updated = passkey.update_credential(&auth_result).unwrap_or(false);
    let new_public_key = if updated {
        Some(
            serde_json::to_vec(&passkey)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?,
        )
    } else {
        None
    };

    if let Some(public_key) = new_public_key {
        sqlx::query(
            "UPDATE operator_webauthn_credentials
             SET public_key = $1, sign_count = $2, last_used_at = now()
             WHERE id = $3",
        )
        .bind(public_key)
        .bind(i64::from(counter))
        .bind(credential_row_id)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE operator_webauthn_credentials
             SET sign_count = $1, last_used_at = now()
             WHERE id = $2",
        )
        .bind(i64::from(counter))
        .bind(credential_row_id)
        .execute(&state.pool)
        .await?;
    }

    session::upgrade_auth_stage(&state.pool, operator.session_id).await?;

    append_audit(
        &state.pool,
        &operator.login,
        "auth.webauthn.authenticate",
        &operator.operator_id.to_string(),
        "",
        &serde_json::json!({}),
    )
    .await?;

    Ok((jar, Json(serde_json::json!({ "ok": true, "auth_stage": "full" }))))
}

async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    if let Some(session_id) = session::parse_session_cookie(&jar) {
        session::delete_session(&state.pool, session_id).await?;
    }
    let jar = session::clear_session_cookie(jar);
    Ok((jar, Json(serde_json::json!({ "ok": true }))))
}

fn unauthenticated_session() -> SessionResponse {
    SessionResponse {
        authenticated: false,
        onboarding_required: false,
        must_change_password: false,
        auth_stage: None,
        role: None,
        login: None,
        csrf_token: None,
    }
}

fn session_response(operator: &OperatorSession, csrf_token: Option<String>) -> SessionResponse {
    SessionResponse {
        authenticated: true,
        onboarding_required: !operator.onboarding_complete,
        must_change_password: operator.must_change_password,
        auth_stage: Some(operator.auth_stage.clone()),
        role: Some(operator.role.clone()),
        login: Some(operator.login.clone()),
        csrf_token,
    }
}

fn validate_login(login: &str) -> ApiResult<()> {
    if login.len() < 3 || login.len() > 32 {
        return Err(ApiError::BadRequest("invalid login length".into()));
    }
    if !login
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::BadRequest("invalid login chars".into()));
    }
    Ok(())
}

fn validate_password(password: &str) -> ApiResult<()> {
    if password.len() < 12 {
        return Err(ApiError::BadRequest("password too short".into()));
    }
    Ok(())
}

pub(crate) fn should_lock_account_after_failure(failed_login_count: i32) -> bool {
    failed_login_count + 1 >= 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_validation() {
        assert!(validate_login("admin").is_ok());
        assert!(validate_login("bad login").is_err());
    }

    #[test]
    fn password_validation() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("longenoughpass").is_ok());
    }

    #[test]
    fn login_lockout_triggers_on_fifth_failure() {
        assert!(!should_lock_account_after_failure(0));
        assert!(!should_lock_account_after_failure(3));
        assert!(should_lock_account_after_failure(4));
    }
}
