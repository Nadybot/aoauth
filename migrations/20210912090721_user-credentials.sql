CREATE TABLE IF NOT EXISTS users
(
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "name" TEXT UNIQUE NOT NULL,
    "password" TEXT NOT NULL
);

CREATE INDEX users_name_idx ON users("name");
