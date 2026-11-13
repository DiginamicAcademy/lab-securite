-- Base de démonstration DIGICHEESE (fil rouge du cours)
-- Thème : fromagerie TPE — refonte d'une app de gestion interne.

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(16) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    price DECIMAL(8,2) NOT NULL,
    stock INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    total DECIMAL(8,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Utilisateurs
-- La version vulnérable stocke des mots de passe en clair ou en MD5.
-- La version sécurisée utilise bcrypt (hash déjà calculés).
INSERT INTO users (username, password_hash, role) VALUES
    ('alice',   'alice123',      'user'),
    ('bruno',   'bruno123',      'user'),
    ('admin',   'admin123',      'admin'),
    ('charlie', '5f4dcc3b5aa765d61d8327deb882cf99', 'user'),
    -- Comptes bcrypt : seuls utilisables sur l'application sécurisée
    ('zoe',     '$2b$12$fojzVU.9R7Lxr8vgeznJbOdo7ap9T3ZSW1EYyAj712R/NDYyhJAJy', 'user'),
    ('marc',    '$2b$12$POhOfHGWnRlR5PjLjy48f.lRNW7gce1uj16mBYb4ey78rmTu9JnGa', 'admin');

INSERT INTO products (name, category, price, stock) VALUES
    ('Comté 12 mois',      'pate-dure',   28.50, 40),
    ('Brie de Meaux',      'pate-molle',  12.90, 25),
    ('Roquefort',          'bleu',        15.40, 18),
    ('Saint-Nectaire',     'pate-molle',  11.20, 30),
    ('Beaufort d''alpage', 'pate-dure',   32.00, 12),
    ('Camembert de Normandie', 'pate-molle', 8.70, 50),
    ('Fourme d''Ambert',   'bleu',        10.30, 22),
    ('Reblochon',          'pate-molle',   9.80, 35);

INSERT INTO comments (username, body) VALUES
    ('alice', 'Le Comté 12 mois est excellent avec un vin blanc du Jura.'),
    ('bruno', 'Quelqu''un sait si le Reblochon arrive vendredi ?'),
    ('admin', 'Pensez à mettre à jour les stocks avant la fin du mois.');
