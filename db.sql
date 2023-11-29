CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    login VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    avatar VARCHAR(255),
    rating INT DEFAULT 0,
    role ENUM('user', 'admin') DEFAULT 'user',
    confirmed BOOLEAN DEFAULT FALSE,
    confirm_token VARCHAR(255),
    token_valid_until DATETIME,
    profile_token VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS categories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    author_id INT NOT NULL,
    title VARCHAR(255),
    publish_date DATETIME,
    status ENUM('active', 'inactive'),
    description TEXT,
    content TEXT,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS post_categories (
    post_id INT,
    category_id INT,
    PRIMARY KEY (post_id, category_id),
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    author_id INT NOT NULL,
    post_id INT NOT NULL,
    publish_date DATETIME,
    parent_id INT,
    content TEXT,
    status ENUM('active', 'inactive'),
    FOREIGN KEY (author_id) REFERENCES users(id),
    FOREIGN KEY (post_id) REFERENCES posts(id)
);

CREATE TABLE IF NOT EXISTS likes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    author_id INT NOT NULL,
    date DATETIME,
    post_id INT,
    comment_id INT,
    type ENUM('like', 'dislike'),
    FOREIGN KEY (author_id) REFERENCES users(id),
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (comment_id) REFERENCES comments(id)
);

CREATE TABLE post_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT,
    file_path VARCHAR(255),
    FOREIGN KEY (post_id) REFERENCES posts(id)
);