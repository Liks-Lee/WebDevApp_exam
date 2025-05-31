-- db_schema.sql - файл для описания схемы базы данных проекта

CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    last_name VARCHAR(64) NOT NULL,
    first_name VARCHAR(64) NOT NULL,
    middle_name VARCHAR(64),
    role_id INT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE genres (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE
);

CREATE TABLE books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    year YEAR NOT NULL,
    publisher VARCHAR(128) NOT NULL,
    author VARCHAR(128) NOT NULL,
    pages INT NOT NULL,
    cover_id INT,
    FOREIGN KEY (cover_id) REFERENCES covers(id) ON DELETE SET NULL
);

CREATE TABLE books_genres (
    book_id INT NOT NULL,
    genre_id INT NOT NULL,
    PRIMARY KEY (book_id, genre_id),
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
    FOREIGN KEY (genre_id) REFERENCES genres(id) ON DELETE CASCADE
);

CREATE TABLE covers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(64) NOT NULL,
    md5_hash VARCHAR(32) NOT NULL UNIQUE
);

CREATE TABLE review_statuses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(32) NOT NULL UNIQUE
);

CREATE TABLE reviews (
    id INT AUTO_INCREMENT PRIMARY KEY,
    book_id INT NOT NULL,
    user_id INT NOT NULL,
    rating INT NOT NULL,
    text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    status_id INT NOT NULL,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (status_id) REFERENCES review_statuses(id),
    UNIQUE (book_id, user_id)
);

-- Заполнение ролей
INSERT INTO roles (name, description) VALUES
('admin', 'Администратор: полный доступ'),
('moderator', 'Модератор: редактирование книг, модерация рецензий'),
('user', 'Пользователь: может оставлять рецензии');

-- Заполнение статусов рецензий
INSERT INTO review_statuses (name) VALUES
('pending'),
('approved'),
('rejected');

-- Заполнение жанров
INSERT INTO genres (name) VALUES
('Фантастика'),
('Детектив'),
('Роман'),
('Поэзия'),
('Научная литература'),
('Приключения'),
('Фэнтези'),
('История'),
('Биография'),
('Драма'),
('Триллер'),
('Ужасы'),
('Комедия'),
('Психология'),
('Детская литература'),
('Энциклопедия'),
('Публицистика'),
('Мемуары'),
('Любовный роман'),
('Саморазвитие');

ALTER TABLE books ADD COLUMN cover_id INTEGER;
ALTER TABLE books ADD CONSTRAINT fk_books_cover_id_covers FOREIGN KEY (cover_id) REFERENCES covers(id) ON DELETE SET NULL;
