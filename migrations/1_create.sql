CREATE TABLE "user"
(
    id       UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(128) NOT NULL,
    email    VARCHAR(255) NOT NULL,
    UNIQUE (username),
    UNIQUE (email)
);