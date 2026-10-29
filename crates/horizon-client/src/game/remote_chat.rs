//! Secure chat on a server's client (ClientPacketListener): the chat
//! session made from the account's chat key pair (setKeyPair), signed chat
//! and signed command arguments (sendChat, sendCommand), and the messages
//! the client acknowledges as seen (LastSeenMessagesTracker,
//! MessageSignatureCache, markMessageAsProcessed). Without a signed-in
//! account, or on a server that plays the account under another profile
//! (offline mode), there is no session and everything goes unsigned.
use super::Game;
use horizon_client::auth::{self, ChatKeyPair};
use horizon_protocol::{
    packets::play::{self, Serverbound as S},
    secure_chat::{self, Body, Encoder, LastSeenTracker, SignatureCache},
};
use std::sync::Arc;

/// ClientPacketListener.sendChatAcknowledgement's threshold.
const ACK_AFTER: i32 = 64;

/// A connection's secure chat state, new with every login packet.
#[derive(Default)]
pub(super) struct SecureChat {
    /// LocalChatSession: the key pair it signs with, and its chain.
    session: Option<(Arc<ChatKeyPair>, Encoder)>,
    tracker: LastSeenTracker,
    cache: SignatureCache,
}

impl SecureChat {
    pub(super) fn signed(&self) -> bool {
        self.session.is_some()
    }
}

/// Crypt.SaltSupplier.getLong: a SecureRandom long.
fn salt() -> i64 {
    let mut bytes = [0u8; 8];
    let _ = horizon_protocol::crypto::random_bytes(&mut bytes);
    i64::from_be_bytes(bytes)
}

/// UUID.randomUUID: version 4, IETF variant.
fn random_uuid() -> u128 {
    let mut bytes = [0u8; 16];
    let _ = horizon_protocol::crypto::random_bytes(&mut bytes);
    bytes[6] = bytes[6] & 0x0f | 0x40;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    u128::from_be_bytes(bytes)
}

impl Game<'_> {
    /// handleLogin: a new session state, and prepareKeyPair.
    pub(super) fn remote_chat_login(&mut self) {
        if let Some(r) = self.remote.as_mut() {
            r.secure_chat = SecureChat::default();
        }
        auth::prepare_chat_keys(true);
        self.update_chat_session();
    }

    /// ClientPacketListener.tick's key refresh (shouldRefreshKeyPair), then
    /// setKeyPair with whatever key pair is ready.
    pub(super) fn tick_chat_session(&mut self) {
        if self.remote.as_ref().is_some_and(|r| r.logged_in) {
            auth::prepare_chat_keys(false);
            self.update_chat_session();
        }
    }

    /// setKeyPair: only for the signed-in account's own profile
    /// (isLocalPlayer), and only when the key pair changed: a new session
    /// (random id, chain from link 0) the server hears of at once.
    fn update_chat_session(&mut self) {
        let Some(account) = auth::current() else {
            return;
        };
        let Some(r) = self.remote.as_mut() else {
            return;
        };
        if !r.logged_in || r.profile() != account.uuid {
            return;
        }
        let Some(keys) = auth::chat_keys() else {
            return;
        };
        if r.secure_chat
            .session
            .as_ref()
            .is_some_and(|(k, _)| Arc::ptr_eq(k, &keys))
        {
            return;
        }
        let id = random_uuid();
        let packet = S::ChatSessionUpdate(play::ChatSessionUpdate {
            session: id,
            expires_at: keys.public.expires_at,
            key: keys.public.key.clone(),
            key_signature: keys.public.signature.clone(),
        });
        r.secure_chat.session = Some((keys, Encoder::new(account.uuid, id)));
        self.send(packet);
    }

    /// ClientPacketListener.sendChat: the last-seen update goes with every
    /// message; the signature only with a chat session.
    pub(super) fn send_signed_chat(&mut self, content: &str) {
        let content: String = content.chars().take(256).collect();
        let (timestamp, salt) = (auth::now_millis(), salt());
        let Some(r) = self.remote.as_mut() else {
            return;
        };
        let chat = &mut r.secure_chat;
        let seen = chat.tracker.update();
        let signature = chat.session.as_mut().and_then(|(keys, encoder)| {
            encoder.sign(
                &keys.private,
                &Body {
                    content: &content,
                    timestamp,
                    salt,
                    last_seen: &seen.last_seen,
                },
            )
        });
        self.send(S::Chat(play::Chat {
            message: content,
            timestamp,
            salt,
            signature: signature.map(|s| s.to_vec()),
            last_seen: seen.update,
        }));
    }

    /// ClientPacketListener.sendCommand: a command with message arguments
    /// (SignableCommand.of over the server's tree) has each of them signed,
    /// all with the same time, salt and last seen; any other command, or any
    /// command without a chat session, goes as the unsigned packet.
    pub(super) fn send_command(&mut self, command: &str) {
        let Some(r) = self.remote.as_mut() else {
            return;
        };
        let arguments = match (&r.commands, r.secure_chat.signed()) {
            (Some(tree), true) => tree
                .parse(command, &self.ui.registries)
                .signable_arguments(tree),
            _ => Vec::new(),
        };
        if arguments.is_empty() {
            self.send(S::ChatCommand(play::ChatCommand {
                command: command.to_owned(),
            }));
            return;
        }
        let (timestamp, salt) = (auth::now_millis(), salt());
        let chat = &mut r.secure_chat;
        let seen = chat.tracker.update();
        let mut signatures = Vec::new();
        if let Some((keys, encoder)) = chat.session.as_mut() {
            for (name, value) in arguments {
                let body = Body {
                    content: &value,
                    timestamp,
                    salt,
                    last_seen: &seen.last_seen,
                };
                if let Some(signature) = encoder.sign(&keys.private, &body) {
                    signatures.push((name, signature.to_vec()));
                }
            }
        }
        self.send(S::ChatCommandSigned(play::ChatCommandSigned {
            command: command.to_owned(),
            timestamp,
            salt,
            arguments: signatures,
            last_seen: seen.update,
        }));
    }

    /// ClientPacketListener.sendUnattendedCommand: a command the player
    /// didn't type (a clicked chat line, a dialog's button, a mod's
    /// command) goes unsigned. Vanilla asks the player before signing one
    /// (multiplayer.confirm_command.signature_required); with no such
    /// screen here, neither a server nor a mod can have the player sign a
    /// message they never saw. A server that enforces secure chat refuses
    /// one with a message argument, as it did before chat was signed.
    pub(super) fn send_unattended_command(&mut self, command: &str) {
        let command = command.trim();
        let command = command.strip_prefix('/').unwrap_or(command);
        if command.is_empty() || !self.chat_abilities().allows(&format!("/{command}")) {
            return;
        }
        self.send(S::ChatCommand(play::ChatCommand {
            command: command.to_owned(),
        }));
    }

    /// handlePlayerChat's bookkeeping: the body's packed last seen against
    /// the signature cache, which then takes the message (push), and
    /// markMessageAsProcessed for a signed one, acknowledged once more than
    /// 64 wait. Horizon shows every message, so each counts as shown.
    pub(super) fn remote_chat_seen(&mut self, p: &play::PlayerChat) {
        let Some(r) = self.remote.as_mut() else {
            return;
        };
        let chat = &mut r.secure_chat;
        let last_seen: Option<Vec<_>> = p
            .last_seen
            .iter()
            .map(|(id, full)| chat.cache.unpack(*id, full.as_deref()))
            .collect();
        let Some(last_seen) = last_seen else {
            log::warn!("Chat message names a signature the cache doesn't hold");
            return;
        };
        let signature = p.signature.as_deref().and_then(secure_chat::signature);
        chat.cache.push(&last_seen, signature.as_ref());
        if let Some(signature) = signature
            && chat.tracker.add_pending(&signature, true)
            && chat.tracker.offset() > ACK_AFTER
        {
            let offset = chat.tracker.take_offset();
            self.send(S::ChatAck(play::ChatAck { offset }));
        }
    }
}
