import express from 'express';
import mysql from 'mysql2';
import bodyParser from 'body-parser';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import multer from 'multer';
import path from 'path';
import jwt from 'jsonwebtoken';
import db from './db.js'

export const setHash = (password) => {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(Math.floor(Math.random() * (10 - 1 + 1)) + 1));
};

export function generateToken() {
	return uuidv4();
}

export async function findUser(value) {
	const [result, _] = await db.promise().query(`SELECT * FROM users WHERE ${value}`);
	try {
		const user = {
			id: result[0].id,
			login: result[0].login,
			password: result[0].password,
			full_name: result[0].full_name,
			email: result[0].email,
			avatar: result[0].avatar,
			rating: result[0].rating,
			role: result[0].role,
			confirmed: result[0].confirmed,
			profile_token: result[0].profile_token
		};
		return user;
	} catch (err) {
		console.error('User is not exist');
		return null;
	}
}


export async function saveUser(login, email, password) {
	const [dataUser, _] = await db.promise().query(
		'INSERT INTO users (login, email, password) VALUES (?, ?, ?)',
		[login, email, password]
	);
	const user = {
		id: dataUser.insertId,
		login: login,
		email: email,
		password: password
	};
	return user;
}


