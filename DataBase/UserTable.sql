CREATE TABLE IF NOT EXISTS user_account (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(256) NOT NULL,
    salt TEXT NOT NULL,
    email VARCHAR(100),
    phone_number VARCHAR(20),
    role VARCHAR(50)
);

