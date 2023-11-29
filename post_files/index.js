import express from 'express';
import session from 'express-session';
import expressThymeleaf from 'express-thymeleaf';
import nodemailer from 'nodemailer';
import path from 'path';
import { TemplateEngine } from 'thymeleaf';
import { pool } from './db.js';
import bcrypt from 'bcrypt';
import shortid from 'shortid';
import User from './models/users.js';

const app = express();
const templateEngine = new TemplateEngine();
const emails = [];
app.use('/public', express.static(path.join(path.resolve(), '/public')));
app.engine('html', expressThymeleaf(templateEngine));
app.set('view engine', 'html');
app.set('views', path.resolve() + '/views');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
	session({
		name: 'amogus',
		secret: 'amogus',
		resave: false,
		saveUninitialized: true,
		cookie: {
			maxAge: 6000000
		}
	})
);

app.get('/', (req, res) => {
  	res.render('index');
});

app.post('/exit', (req, res) => {
  	res.redirect('/');
});

app.get('/reminder-password', (_, res) => {
  	getEmails();
	console.log(emails);
  	res.render('form-reminder');
});

app.post('/push-massege', async (req, res) => {
	const email = req.body.email;
	if (!emails.includes(email))
	{
		res.render('form-reminder', {
			errorClass: 'alert alert-danger text-center',
			errorMass: 'Email not found'
		});
		return;
	}
	const newPass = shortid.generate();
	const currentUser = new User();
	currentUser.find(email);
	setTimeout(() => {
		currentUser.password = setHash(newPass);
		currentUser.update = true;
		currentUser.save();
		main(email, currentUser, newPass).catch(console.error);
		res.render('index', {
		confirmClass: 'alert alert-success',
		confirmMass: 'Password has been sent by email',
		});
	}, 100);
});

app.listen(3000);

const getEmails = async () => {
	const [result, _] = await pool.promise().query('SELECT email FROM users;');
	result.map(({ email }) => emails.push(email));
};

const main = async (email, { login, ..._ }, password) => {
	const transporter = nodemailer.createTransport({
		host: 'smtp.ethereal.email',
		port: 587,
		auth: {
		user: 'rogelio.wiza2@ethereal.email',
		pass: 'WQgJZJCjJ2zg5hDpVb'
		},
	});

	let info = await transporter.sendMail({
		from: '"anonymous 👻" <anon@example.com>',
		to: email,
		subject: 'Reset password',
		html:
			`<h1>Reset password</h1>
			<br>
			<p>Login: ${login}</p>
			<p>Password: ${password}</p>`
	});
};

const setHash = (password) => {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(Math.floor(Math.random() * (10 - 1 + 1)) + 1));
};
