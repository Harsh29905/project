create database bank_db;
use bank_db;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(500) NOT NULL,  -- Increased size for encrypted data
    password_hash VARCHAR(128) NOT NULL,
    account_id VARCHAR(500) NOT NULL,  -- Increased size for encrypted data
    balance DECIMAL(10, 2) DEFAULT 0.00
);
select * from users;
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    transaction_type VARCHAR(500) NOT NULL,  -- Increased size for encrypted data
    amount DECIMAL(10, 2) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    balance_after DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
select * from transactions;
