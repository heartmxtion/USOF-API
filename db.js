import mysql from 'mysql2';

const db = mysql.createConnection({
	host: 'localhost',
	port: 3306,
	user: 'root',
	password: 'root',
	database: 'usof'
});

db.connect((err) => {
	if (err) {
		console.error('Ошибка подключения к базе данных:', err);
	} else {
		console.log('Подключено к базе данных');
	}
});

export default db;