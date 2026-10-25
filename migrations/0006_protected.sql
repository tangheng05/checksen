CREATE TABLE protected_chats (
    chat_id BIGINT PRIMARY KEY,
    since TIMESTAMPTZ NOT NULL DEFAULT now()
);
