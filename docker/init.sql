-- Database init (runs once, on first container start).
-- Creates the application roles and the database. Passwords here are
-- DEVELOPMENT ONLY — production credentials come from Secrets Manager.
CREATE USER null_owner WITH PASSWORD 'dev_owner_password';
CREATE USER null_app WITH PASSWORD 'dev_app_password';
CREATE DATABASE null_itsm OWNER null_owner;
GRANT ALL PRIVILEGES ON DATABASE null_itsm TO null_owner;
GRANT CONNECT ON DATABASE null_itsm TO null_app;
