CREATE TABLE IF NOT EXISTS characters
(
    "user_id" INTEGER REFERENCES users("id") ON DELETE CASCADE NOT NULL,
    "name" TEXT UNIQUE NOT NULL,
    "id" INTEGER UNIQUE NOT NULL
);

CREATE INDEX characters_user_idx ON characters("user_id");
CREATE INDEX characters_name_idx ON characters("name");
CREATE INDEX characters_id_idx ON characters("id");
