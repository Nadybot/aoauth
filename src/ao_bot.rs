use std::{collections::HashMap, sync::Arc, time::Duration};

use dashmap::DashMap;
use nadylib::{
    models::{Channel, Message},
    packets::{
        ClientLookupPacket, ClientLookupResultPacket, LoginSelectPacket, MsgPrivatePacket,
        OutgoingPacket, SerializedPacket,
    },
    AOSocket, ReceivedPacket, SocketConfig,
};
use sqlx::SqlitePool;
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{UnboundedReceiver as MpscReceiver, UnboundedSender as MpscSender},
        oneshot::{channel as oneshot_channel, Sender as OneshotSender},
    },
    time::sleep,
};

use crate::config::CONFIG;

pub type Verifications = Arc<DashMap<String, i64>>;
pub type PendingQueries = Arc<DashMap<String, OneshotSender<ClientLookupResultPacket>>>;

#[derive(Clone)]
pub struct CharacterQuery {
    pub sender: MpscSender<SerializedPacket>,
    pub pending: PendingQueries,
}

impl CharacterQuery {
    pub async fn lookup(&self, character_name: String) -> Option<u32> {
        let (tx, rx) = oneshot_channel();
        self.pending.insert(character_name.clone(), tx);

        let packet = ClientLookupPacket { character_name };
        self.sender.send(packet.serialize()).unwrap();

        let result = rx.await.unwrap();

        if result.exists {
            Some(result.character_id)
        } else {
            None
        }
    }
}

async fn wait_server_ready(addr: &str) {
    while TcpStream::connect(addr).await.is_err() {
        sleep(Duration::from_secs(10)).await;
    }
}

pub async fn run(
    mut receiver: MpscReceiver<SerializedPacket>,
    verifications: Verifications,
    pool: SqlitePool,
    queries: PendingQueries,
) -> nadylib::Result<()> {
    let mut connected = false;

    'connect_loop: loop {
        tracing::info!("Waiting for chat server to be available");
        wait_server_ready("chat.d1.funcom.com:7105").await;

        let mut socket = AOSocket::connect("chat.d1.funcom.com:7105", SocketConfig::default())
            .await
            .unwrap();

        let mut id_to_user_mapping: HashMap<u32, String> = HashMap::new();

        'read_loop: loop {
            tokio::select! {
                packet = socket.read_packet() => {
                    if let Ok(packet) = packet {
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
                                    tracing::error!("Character {} not found, not retrying", CONFIG.bot_character);
                                    break 'connect_loop;
                                }
                            }
                            ReceivedPacket::LoginOk => {
                                connected = true;
                                tracing::info!("Logged in to AO chat servers");
                            },
                            ReceivedPacket::LoginError(login_error) => {
                                tracing::error!(
                                    "Failed to log in to AO chat servers, not retrying: {}",
                                    login_error.message
                                );
                                break 'connect_loop;
                            }
                            ReceivedPacket::ClientName(client_name) => {
                                id_to_user_mapping.insert(client_name.character_id, client_name.character_name);
                            }
                            ReceivedPacket::ClientLookup(client_lookup_result) => {
                                if let Some((_, sender)) = queries.remove(&client_lookup_result.character_name)
                                {
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
                    } else {
                        connected = false;
                        tracing::error!("Failed to read packet from AO chat servers, reconnecting in 10s");
                        sleep(Duration::from_secs(10)).await;
                        break 'read_loop;
                    }
                }
                to_send = receiver.recv(), if connected => {
                    if let Some(to_send) = to_send {
                        socket.send_raw(to_send.0, to_send.1).await?;
                    }
                }
            }
        }
    }

    Ok(())
}
