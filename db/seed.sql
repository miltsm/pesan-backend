CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE users (
	user_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	user_handle varchar(80) NOT NULL UNIQUE,
	display_name varchar(80),
	created_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	created_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
	created_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
	tags text[] NOT NULL DEFAULT '{}',
	open_hour time NOT NULL DEFAULT '08:30',
	closing_hour time NOT NULL DEFAULT '21:30',
	contacts jsonb,	
	operation_days open_day[] NOT NULL DEFAULT ARRAY['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']::open_day[],
	location text,
	customer_order_keys text[],
	order_distance integer DEFAULT 100, -- 100 meter from seller shop
	logo_url text,
	banner_img_url text,
	created_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE
);

CREATE TABLE roles (
	role_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	edit_shop boolean DEFAULT false,
	open_close_shop boolean NOT NULL DEFAULT false,
	create_products boolean NOT NULL DEFAULT false,
	edit_products boolean NOT NULL DEFAULT false,
	delete_products boolean NOT NULL DEFAULT false,
	create_orders boolean NOT NULL DEFAULT false,
	edit_orders boolean NOT NULL DEFAULT false,
	create_roles boolean NOT NULL DEFAULT false,
	edit_roles boolean NOT NULL DEFAULT false,
	delete_roles boolean NOT NULL DEFAULT false,
	created_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at timestamp WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	created_by uuid REFERENCES users ON DELETE RESTRICT,
	user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
	shop_id uuid NOT NULL UNIQUE REFERENCES shops ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION limit_shop_row_insert()
RETURNS TRIGGER AS $$
BEGIN
	IF (SELECT count(*) FROM shops) > 1 THEN
		RAISE EXCEPTION 'Cannot insert more than 1 row at once';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER check_insert_limit
BEFORE INSERT ON shops
FOR EACH STATEMENT
EXECUTE FUNCTION limit_shop_row_insert();

CREATE OR REPLACE FUNCTION create_owner_role()
RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO roles (edit_shop, open_close_shop, create_products, edit_products, delete_products, create_orders, edit_orders, create_roles, edit_roles, delete_roles, created_by, shop_id, user_id)
	VALUES (true, true, true, true, true, true, true, true, true, true, NEW.user_id, NEW.shop_id, NEW.user_id);
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER create_owner_role_after_shop_insert
AFTER INSERT ON shops
FOR EACH ROW
EXECUTE FUNCTION create_owner_role();

CREATE VIEW shop_roles AS
SELECT
	s.shop_id,
	s.name,
	s.tags,
	s.open_hour,
	s.closing_hour,
	s.contacts,
	s.operation_days,
	s.location,
	s.updated_at AS shop_updated_at,
	r.role_id,
	r.edit_shop,
	r.open_close_shop,
	r.create_products,
	r.edit_products,
	r.delete_products,
	r.create_orders,
	r.edit_orders,
	-- roles are for future feature: 1 shops, M staffs
	r.updated_at AS role_updated_at,
	r.user_id
FROM
	shops s
LEFT JOIN
	roles r ON s.shop_id = r.shop_id;
