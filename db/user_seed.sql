CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE users (
	user_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	user_handle varchar(80) NOT NULL UNIQUE,
	display_name varchar(80),
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP
);

CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
	New.updated_at = LOCALTIMESTAMP;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_user_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TABLE passkeys (
	passkey_id bytea PRIMARY KEY,
	public_key bytea UNIQUE NOT NULL,
	attestation_type varchar(50),
	transport text[],
	flags jsonb,
	authenticator_aaguid bytea,
	sign_count integer DEFAULT 0,
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP,
	user_id uuid not null REFERENCES users ON DELETE CASCADE
);

CREATE TRIGGER update_passkey_timestamp
BEFORE UPDATE ON passkeys
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE UNLOGGED TABLE passkey_sessions (
	user_handle varchar(80) PRIMARY KEY UNIQUE NOT NULL,
	temp_user jsonb,
	session_data jsonb,
	expires_at timestamp
);

CREATE TABLE passwords (
	password_id uuid PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
	hashed text NOT NULL,
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP
);

CREATE TRIGGER update_password_timestamp
BEFORE UPDATE ON passwords
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();
