CREATE TABLE users(
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    PRIMARY KEY (username)
);


CREATE TABLE posts(
    id VARCHAR(36) NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    PRIMARY KEY( id),
    FOREIGN KEY (user_id) REFERENCES users(username)
);
