CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE products (
	product_id uuid UNIQUE PRIMARY KEY DEFAULT uuid_generate_v4(),
	name varchar(128) NOT NULL,
	description varchar(256),
	unit varchar(15) NOT NULL DEFAULT 'unit',
	price numeric CONSTRAINT positive_price CHECK (price > 0 AND price < 100),
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP
);
CREATE TYPE open_day AS ENUM ('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday');
-- Product can have multiple categories, Category belongs to multiple product; M:N
CREATE TABLE categories (
	category_id uuid UNIQUE PRIMARY KEY DEFAULT uuid_generate_v4(),
	name varchar(128) NOT NULL,
	description varchar(256),
	open_hour time DEFAULT '08:30',
	closing_hour time DEFAULT '21:30',
	weekly open_day[] NOT NULL DEFAULT ARRAY['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']::open_day[],
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP
);
CREATE TABLE product_categories (
	product_id uuid REFERENCES products ON DELETE CASCADE,
	category_id uuid REFERENCES categories ON DELETE RESTRICT,
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP,
	PRIMARY KEY (product_id, category_id)
);
-- 1 Product : M Images
CREATE TABLE images (
	image_id uuid UNIQUE PRIMARY KEY DEFAULT uuid_generate_v4(),
	filename text DEFAULT CONCAT('image_', TO_CHAR(LOCALTIMESTAMP, 'YYYYMMDD24MI'), '.webp'),
	mimetype varchar(12) DEFAULT 'image/webp',
	url text,	
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP,
	product_id uuid REFERENCES products ON DELETE CASCADE
);

CREATE TABLE addons (
	addon_id uuid UNIQUE PRIMARY KEY DEFAULT uuid_generate_v4(),
	name varchar(128) NOT NULL,
	description varchar(256),
	charge numeric,
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP
);

CREATE TABLE product_addons (
	product_id uuid REFERENCES products ON DELETE CASCADE,
	addon_id uuid REFERENCES addons ON DELETE RESTRICT,
	created_at timestamp DEFAULT LOCALTIMESTAMP,
	updated_at timestamp DEFAULT LOCALTIMESTAMP,
	PRIMARY KEY (product_id, addon_id)
);
