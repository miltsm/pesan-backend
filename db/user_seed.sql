CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE users (
	user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	user_handle varchar(80) NOT NULL UNIQUE,
	display_name varchar(180),
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP
);

CREATE TABLE passkeys (
	passkey_id bytea PRIMARY KEY,
	user_id uuid not null REFERENCES users ON DELETE CASCADE,
	public_key bytea UNIQUE NOT NULL,
	attestation_type varchar(50),
	transport text[],
	flags jsonb,
	authenticator_aaguid bytea,
	sign_count integer DEFAULT 0,
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP
);
