CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE users (
	user_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	user_handle varchar(80) NOT NULL UNIQUE,
	display_name varchar(80),
	created_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
	New.updated_at = CURRENT_TIMESTAMP;
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
	created_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE
);

CREATE TRIGGER update_passkey_timestamp
BEFORE UPDATE ON passkeys
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- one of the alternative to replace redis, but discarded
CREATE UNLOGGED TABLE passkey_sessions (
	user_handle varchar(80) PRIMARY KEY UNIQUE NOT NULL,
	temp_user jsonb,
	session_data jsonb,
	expires_at timestamp
);

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION hash_password()
RETURNS trigger AS $$
BEGIN
	NEW.hashed = crypt(NEW.hashed, gen_salt('bf', 10));
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE passwords (
	password_id uuid PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
	hashed text NOT NULL,
	created_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	user_id uuid UNIQUE NOT NULL REFERENCES users ON DELETE CASCADE
);

CREATE TRIGGER before_insert_passwords
BEFORE INSERT ON passwords
FOR EACH ROW
EXECUTE FUNCTION hash_password();

CREATE TRIGGER update_password_timestamp
BEFORE UPDATE ON passwords
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE VIEW user_passkeys AS
SELECT
	u.user_id,
	u.user_handle,
	u.display_name,
	p.passkey_id,
	p.public_key,
	p.attestation_type,
	p.transport,
	p.flags,
	p.authenticator_aaguid,
	p.sign_count,
	p.created_at
FROM
	users u
LEFT JOIN
	passkeys p ON u.user_id = p.user_id;

CREATE VIEW user_profiles AS
SELECT
	up.user_id, 
	up.user_handle, 
	up.display_name, 
	up.passkey_id,
	COUNT(up.passkey_id) AS passkey_count, 
	pw.updated_at AS last_password_updated_at
FROM
	user_passkeys up 
LEFT JOIN
	passwords pw ON up.user_id = pw.user_id
GROUP BY
	up.user_id,
	up.user_handle,
	up.display_name,
	up.passkey_id, 
	pw.updated_at;

CREATE TYPE open_day AS ENUM ('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday');

CREATE TABLE shops (
	shop_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	name varchar(80) NOT NULL,
	tags text[],
	open_hour time WITH TIME ZONE NOT NULL DEFAULT '08:30',
	closing_hour time WITH TIME ZONE NOT NULL DEFAULT '21:30',
	contacts text[],	
	operation_days open_day[] NOT NULL DEFAULT ARRAY['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']::open_day[],
	locations text[],
	customer_order_keys text[],
	auto_re_stock_next_day boolean DEFAULT true,
	order_distance integer DEFAULT 100, -- 100 meter from seller shop
	logo_url text,
	banner_img_url text,
	created_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE 
);

CREATE TABLE roles (
	role_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	can_edit_shop boolean DEFAULT false,
	can_delete_shop boolean DEFAULT false,
	can_open_close_shop boolean DEFAULT false,
	can_create_product boolean DEFAULT false,
	can_edit_product boolean DEFAULT false,
	can_delete_product boolean DEFAULT false,
	can_create_order boolean DEFAULT false,
	can_edit_order boolean DEFAULT false,
	created_by uuid NOT NULL REFERENCES users,
	user_id uuid NOT NULL UNIQUE REFERENCES users ON DELETE CASCADE,
	shop_id uuid NOT NULL UNIQUE REFERENCES shops ON DELETE CASCADE
);
