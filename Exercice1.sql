DROP TABLE IF EXISTS utilisateurs;

CREATE TABLE utilisateurs ( 
	id SERIAL PRIMARY KEY, 
	email VARCHAR(255) UNIQUE NOT NULL CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'), 
	password_hash TEXT NOT NULL, 
	nom VARCHAR(100), 
	prenom VARCHAR(100), 
	actif BOOLEAN DEFAULT TRUE, 
	date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
	date_modification TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
	);
