//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! In-memory WebAuthn challenge storage with TTL.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

pub const WEBAUTHN_CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct ChallengeEntry<T> {
    pub value: T,
    pub created_at: Instant,
}

impl<T> ChallengeEntry<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            created_at: Instant::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > WEBAUTHN_CHALLENGE_TTL
    }
}

#[derive(Clone, Default)]
pub struct ChallengeStore<T> {
    inner: Arc<Mutex<HashMap<Uuid, ChallengeEntry<T>>>>,
}

impl<T> ChallengeStore<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, key: Uuid, value: T) {
        let mut map = self.inner.lock().expect("challenge store lock");
        purge_expired(&mut map);
        map.insert(key, ChallengeEntry::new(value));
    }

    pub fn remove(&self, key: &Uuid) -> Option<T> {
        let mut map = self.inner.lock().expect("challenge store lock");
        purge_expired(&mut map);
        let entry = map.remove(key)?;
        if entry.is_expired() {
            return None;
        }
        Some(entry.value)
    }
}

pub type RegistrationChallengeStore = ChallengeStore<PasskeyRegistration>;
pub type AuthenticationChallengeStore = ChallengeStore<PasskeyAuthentication>;

fn purge_expired<T>(map: &mut HashMap<Uuid, ChallengeEntry<T>>) {
    map.retain(|_, entry| !entry.is_expired());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_entry_not_returned() {
        let store = ChallengeStore::<String>::new();
        let id = Uuid::new_v4();
        store.insert(id, "challenge".into());
        {
            let mut map = store.inner.lock().unwrap();
            if let Some(entry) = map.get_mut(&id) {
                entry.created_at = Instant::now() - WEBAUTHN_CHALLENGE_TTL - Duration::from_secs(1);
            }
        }
        assert!(store.remove(&id).is_none());
    }
}
