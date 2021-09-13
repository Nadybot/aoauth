use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use nadylib::{
    client_socket::SocketSendHandle,
    models::{Channel, Message},
    packets::{ClientLookupPacket, ClientLookupResultPacket, LoginSelectPacket, MsgPrivatePacket},
    AOSocket, ReceivedPacket,
};
use sqlx::SqlitePool;
use tokio::sync::oneshot::{channel, Sender};

use crate::config::CONFIG;

pub type Verifications = Arc<DashMap<String, i64>>;
pub type PendingQueries = Arc<DashMap<String, Sender<ClientLookupResultPacket>>>;

#[derive(Clone)]
pub struct CharacterQuery {
    pub sender: SocketSendHandle,
    pub pending: PendingQueries,
}

impl CharacterQuery {
    pub async fn lookup(&self, character_name: String) -> Option<u32> {
        let (tx, rx) = channel();
        self.pending.insert(character_name.clone(), tx);

        let packet = ClientLookupPacket { character_name };
        self.sender.send(packet).await.unwrap();

        let result = rx.await.unwrap();

        if result.exists {
            Some(result.character_id)
        } else {
            None
        }
    }
}

pub async fn run(
    mut socket: AOSocket,
    verifications: Verifications,
    pool: SqlitePool,
    queries: PendingQueries,
) -> nadylib::Result<()> {
    let mut id_to_user_mapping: HashMap<u32, String> = HashMap::new();

    while let Ok(packet) = socket.read_packet().await {
        match packet {
            ReceivedPacket::LoginSeed(seed) => {
                socket
                    .login(&CONFIG.bot_username, &CONFIG.bot_password, &seed.login_seed)
                    .await?;
            }
            ReceivedPacket::LoginCharlist(charlist) => {
                let character = charlist
                    .characters
                    .iter()
                    .find(|character| character.name == CONFIG.bot_character);

                if let Some(character) = character {
                    socket
                        .send(LoginSelectPacket {
                            character_id: character.id,
                        })
                        .await?;
                } else {
                    tracing::error!("Character {} not found", CONFIG.bot_character);
                    break;
                }
            }
            ReceivedPacket::LoginOk => tracing::info!("Logged in to AO chat servers"),
            ReceivedPacket::LoginError(login_error) => {
                tracing::error!(
                    "Failed to log in to AO chat servers: {}",
                    login_error.message
                );
                break;
            }
            ReceivedPacket::ClientName(client_name) => {
                id_to_user_mapping.insert(client_name.character_id, client_name.character_name);
            }
            ReceivedPacket::ClientLookup(client_lookup_result) => {
                if let Some((_, sender)) = queries.remove(&client_lookup_result.character_name) {
                    sender.send(client_lookup_result).unwrap();
                }
            }
            ReceivedPacket::MsgPrivate(msg_private) => {
                let sender_id = msg_private.message.sender.unwrap();

                if let Some((_, user_id)) = verifications.remove(&msg_private.message.text) {
                    let sender_name = id_to_user_mapping.get(&sender_id).unwrap();
                    let successful = sqlx::query!(
                        r#"INSERT INTO characters ("user_id", "name", "id") VALUES (?, ?, ?);"#,
                        user_id,
                        sender_name,
                        sender_id
                    )
                    .execute(&pool)
                    .await
                    .is_ok();

                    let message = if successful {
                        "You have been added to the alt list. Please reload the page in your browser now."
                    } else {
                        "Failed to add you to the alt list. This means you've already been added to someone else's."
                    };

                    let packet = MsgPrivatePacket {
                        message: Message {
                            sender: None,
                            channel: Channel::Tell(sender_id),
                            text: message.to_string(),
                            send_tag: String::from("\u{0}"),
                        },
                    };
                    socket.send(packet).await?;
                } else {
                    let packet = MsgPrivatePacket {
                        message: Message {
                            sender: None,
                            channel: Channel::Tell(sender_id),
                            text: String::from("Invalid verification token. Please grab a new one, this one might have expired."),
                            send_tag: String::from("\u{0}"),
                        },
                    };
                    socket.send(packet).await?;
                }
            }
            _ => {}
        }
    }

    tracing::error!("Failed to read packet from AO chat servers");

    Ok(())
}
