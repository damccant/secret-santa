const config = require("./config.json");
const strings = require("./strings.json");

const express = require("express");
// use DatabaseSync for compatibility with older Node.JS versions
const { DatabaseSync, constants } = require("node:sqlite");

const { argon2Sync, randomBytes, timingSafeEqual } = require("node:crypto");
const secret = Buffer.from(config.secret, 'base64'); // pepper

function toB64NoPad(str) {
	return str.toString('base64').replace(/={1,2}$/, '');
}

function hashPassword(plaintext) {
	const nonce = randomBytes(16); // salt
	const algorithm = 'argon2id'
	const params = {
		message: plaintext,
		nonce,
		parallelism: 4,
		memory: 65536,
		passes: 3,
		tagLength: 64,
		secret
	}
	argon2Sync(algorithm, params);
	const hash = argon2Sync(algorithm, params);
    return [`${algorithm}`, `m=${params.memory},t=${params.passes},p=${params.parallelism}`, toB64NoPad(nonce), toB64NoPad(hash)].join('$');
}

// console.log(toB64NoPad(randomBytes(64)));

function verifyPassword(password, hash) {
	const p = hash.split('$');
	const b = Object.fromEntries(p[1].split(',').map(p => p.split('=')));
	const nonce = Buffer.from(p[2], 'base64');
	const expected = Buffer.from(p[3], 'base64');
	const actual = argon2Sync(p[0], {
		message: password,
		nonce: nonce,
		parallelism: +b.p,
		memory: +b.m,
		passes: +b.t,
		tagLength: expected.length,
		secret
	});
	return timingSafeEqual(actual, expected);
}

var db = new DatabaseSync("./db/db.sqlite",
	{
		// DENY LOADING COMPILED EXTENSIONS
		allowExtension: false,
		enabledDoubleQuotedStringLiterals: false,
		defensive: true,
		limits: {
			"SQLITE_LIMIT_ATTACHED": 0,
			"SQLITE_LIMIT_EXPR_DEPTH": 50
		}
	}
);

db.setAuthorizer((actionCode, arg1, arg2, dbName, triggerName) => {
	if(actionCode == constants.SQLITE_ATTACH)
		return constants.SQLITE_DENY;
	if(actionCode == constants.SQLITE_LOAD_EXTENSION)
		return constants.SQLITE_DENY;
	if (actionCode === constants.SQLITE_PRAGMA) {
		// Optionally whitelist benign pragmas like 'foreign_keys' or 'busy_timeout' [1.2.2, 2.3]
		const allowedPragmas = ['foreign_keys', 'busy_timeout', 'table_info', 'index_list'];
		if (!allowedPragmas.includes(arg1.toLowerCase()))
			return constants.SQLITE_DENY; 
	}
	// --- PERMITTED ADMIN COMMANDS ---
	// Explicitly allow schema mutations since they are required for administrative panel
	const allowedAdminActions = [
		constants.SQLITE_SELECT, constants.SQLITE_READ,       // Querying [1.5]
		constants.SQLITE_INSERT, constants.SQLITE_UPDATE,     // Data Modification
		constants.SQLITE_DELETE,                              // Purging Records
		constants.SQLITE_CREATE_TABLE, constants.SQLITE_DROP_TABLE, // Schema Changes
		constants.SQLITE_CREATE_INDEX, constants.SQLITE_DROP_INDEX, // Index Optimization
		constants.SQLITE_ALTER_TABLE                          // Table Structure Shifts
	];

	if (allowedAdminActions.includes(actionCode)) {
		return constants.SQLITE_OK; // Safe database actions
	}

	// Default block for any undocumented or high-risk operational edge-cases
	return constants.SQLITE_DENY; 
});

const FIELDS = [
	{name: "email", sql_type: "VARCHAR(100) NOT NULL"},
	{name: "name", sql_type: "TEXT NOT NULL"},
	{name: "color", sql_type: "CHAR(7) NOT NULL"},
	{name: "addl_color", sql_type: "TEXT"},
	{name: "shirt_size", sql_type: "VARCHAR(3) NOT NULL"},
	{name: "pant_size", sql_type: "VARCHAR(10) NOT NULL"},
	{name: "shoe_size", sql_type: "REAL NOT NULL"},
	{name: "sports", sql_type: "TEXT"},
	{name: "snacks", sql_type: "TEXT NOT NULL"},
	{name: "drinks", sql_type: "TEXT NOT NULL"},
	{name: "restaurant", sql_type: "TEXT NOT NULL"},
	{name: "hobbies", sql_type: "TEXT"},
	{name: "like", sql_type: "TEXT NOT NULL"},
	{name: "dislike", sql_type: "TEXT NOT NULL"},
	{name: "allergies", sql_type: "TEXT NOT NULL"},
	{name: "extra", sql_type: "TEXT"},
];

try {
	const f = FIELDS.map(f => f.name + " " + f.sql_type).join(',');
	db.exec(`
		CREATE TABLE users(
			id INTEGER PRIMARY KEY,
			submission_pass VARCHAR(8) NOT NULL,
			lang CHAR(2) NOT NULL,
			timestamp DATETIME NOT NULL,
			${f}
		);
		`);
} catch(e) { /* Table already exists, ignore */ }

// try {
// 	db.exec(`
// 		CREATE TABLE admin(
// 			user VARCHAR(32) PRIMARY KEY,
// 			pass CHAR(32) NOT NULL
// 		);`);
// 	db.prepare(`
// 		INSERT INTO admin(user, pass)
// 		VALUES(?, ?);
// 		`).all("admin", argon);
// } catch(e) { /* Table already exists, ignore */ }

var app = express();

app.set('view engine', 'ejs');
app.set('trust proxy', config.trust_proxy);
app.use(express.urlencoded({ limit: '100kb' }));

// app.get("/", (req, res) => {
// 	res.redirect("/admin");
// });

// app.get("/form", (req, res) => {
// 	res.redirect("/form/en/a");
// });

// app.get("form/:lang", (req, res) => {
// 	res.redirect(`/form/${req.params.lang}/a`);
// });

app.get("/form/:lang/:submission_pass", (req, res) => {
	const s = strings[req.params.lang];
	if(s === undefined)
		res.status(404).send();
	else
		res.render('form', {s: s});
});

app.post("/form/:lang/:submission_pass", (req, res) => {
	const s = strings[req.params.lang];
	if(s === undefined)
	{
		res.status(404).send();
		return;
	}
	
	try {
		// SQL injection not possible because the fields are hardcoded above
		var stmt = db.prepare(`
			INSERT INTO users(submission_pass, lang, timestamp, ${FIELDS.map(f => f.name).join(',')})
			VALUES (:submission_pass, :lang, :timestamp, ${FIELDS.map(f => ":" + f.name).join(',')});
			`);
		var e = {
			":submission_pass": req.params.submission_pass,
			":lang": req.params.lang,
			":timestamp": Date.now()
		};
		for(var f of FIELDS) {
			var value = req.body[f.name];
			if(value === "" || value === undefined)
				value = null;
			e[":" + f.name] = value;
		}
		stmt.all(e);
		res.render('complete', {s: s});
	} catch(e) {
		console.log(e);
		res.status(400).render('error', {s: s});
	}
});

if(!config.lockdown)
{
	const cookieParser = require("cookie-parser");
	app.use(cookieParser());

	var sessions = [];

	function checkLogin(req) {
		var session = req.cookies["session"];
		if(!session)
			return null;
		session = session.split(',')[0];
		for(const s of sessions)
		{
			if(s.cookie.length === session.length)
			{
				if(timingSafeEqual(Buffer.from(s.cookie), Buffer.from(session)))
					return true;
			}
			else
			{
				// obviously wrong token, but waste a little time
				timingSafeEqual(Buffer.from(s.cookie), Buffer.from(s.cookie));
			}
		}
		for(var i = 0; i < Math.random() * 10000; ++i)
			; // waste time to prevent timing attacks
		return false;
	}

	app.get("/login", (req, res) => {
		if(checkLogin(req)) // already logged in?
		{
			res.redirect("/admin");
			return;
		}
		res.render('login', { s: strings.en });
	});

	app.post("/login", (req, res) => {
		var login_success = req.body.username && verifyPassword(req.body.password, config.password);
		if(login_success)
		{
			const new_session = randomBytes(32).toString('base64').replace('=', '#');
			sessions.push({user: req.body.username, cookie: new_session });
			res.header("Set-Cookie", `session=${new_session},HttpOnly,SameSite=Lax,Secure`);
			res.redirect("/admin");
		}
		else
			res.status(401).render('login', { s: strings.en });
	});

	app.use((req, res, next) => {
		if(checkLogin(req))
			next();
		else
			res.redirect("/login");
	});

	app.get("/admin", (req, res) => {
		res.render('admin', { s: strings.en, sessions });
	});

	app.post("/logout", (req, res) => {
		// for extra security, close all sessions
		sessions = [];
		res.redirect('/login');
	});

	app.get("/sql", (req, res) => {
		res.render('sql', { s: strings.en, input: "", results: "Enter SQL query" });
	});

	app.post("/sql", (req, res) => {
		var results;
		try {
			results = JSON.stringify(db.prepare(req.body.input).all(), null, ' ');
		} catch(err) {
			results = err;
		}
		res.render('sql', { s: strings.en, input: req.body.input, results });
	});

	app.get("/list", (req, res) => {
		const c = db.prepare("SELECT * FROM users;").all();
		res.render('list', { s: strings.en, FIELDS, results: c });
	});

	app.get("/list/:submission_pass", (req, res) => {
		const c = db.prepare("SELECT * FROM users WHERE submission_pass = ?;").all(req.params.submission_pass);
		res.render('list', { s: strings.en, FIELDS, results: c });
	});

	function shuffleDerangement(array) {
		if (array.length < 2) {
			throw new Error("Derangement is impossible with fewer than 2 elements.");
		}

		// Create a shallow copy to compare against the original layout
		const original = [...array];
		let shuffled = [...array];
		let hasConflict = true;

		while (hasConflict) {
			// 1. Perform standard Fisher-Yates shuffle
			for (let i = shuffled.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
			}

			// 2. Check if ANY item is still in its starting position
			hasConflict = shuffled.some((item, index) => item === original[index]);
		}

		return shuffled;
	}

	function load_giver_taker_info(giver_id, taker_id) {
		var ret = {
			giver: db.prepare("SELECT email, lang, name FROM users WHERE id = ?;").all(giver_id)[0],
			taker: db.prepare("SELECT * FROM users WHERE id = ?;").all(taker_id)[0]
		};
		ret.s = strings[ret.giver.lang];
		if(ret.s === undefined)
			ret.s = strings.en;
		ret.support = config.email.auth.user;
		return ret;
	}

	function make_givers_takers(submission_pass) {
		const givers = db
			.prepare("SELECT id FROM users WHERE submission_pass = ?;")
			.all(submission_pass)
			.map(g => g.id);
		const takers = shuffleDerangement(givers);
		return {givers, takers};
	}

	app.get("/derange/:submission_pass", (req, res) => {
		var {givers, takers} = make_givers_takers(req.params.submission_pass);

		res.header("Content-Type", "application/json");
		res.send(JSON.stringify({givers, takers}));
	});

	function sanitizeNumber(num) {
		return isNaN(0 + num) ? 0 : 0 + num;
	}

	app.post("/email_html", (req, res) => {
		if(isNaN(+req.body.giver) || isNaN(+req.body.taker)) {
			res.redirect('/admin');
			return;
		}
		const giver_id = +req.body.giver;
		const taker_id = +req.body.taker;
		const p = load_giver_taker_info(giver_id, taker_id);
		res.render("email_html", p);
	});

	app.get("/email_text/:giver/:taker", (req, res) => {
		const p = load_giver_taker_info(req.params.giver, req.params.taker);
		res.header("Content-Type", "text/plain");
		res.render("email_text", p);
	});

	const nodemailer = require("nodemailer");

	const mail = nodemailer.createTransport(config.email);

	async function sendMail(to, subject, html) {
		return new Promise((resolve, reject) => mail.sendMail({
			from: config.email.user,
			to, subject, html},
			(err, info) => {
				if(err)
					reject(err);
				else
					resolve(info);
			}
		));
	}

	async function renderHtml(res, file, data) {
		return new Promise((resolve, reject) =>
			res.render(file, data, (err, html) => {
				if(err)
					reject(err);
				else
					resolve(html);
			}));
	}

	app.post("/run", async (req, res) => {
		const {givers, takers} = make_givers_takers(req.body.submission_pass);
		const success = {};

		for(var i = 0; i < givers.length; ++i) {
			const p = load_giver_taker_info(givers[i], takers[i]);
			const html = await renderHtml(res, "email_html", p);
			success[p.giver.email] = await sendMail(p.giver.email, strings[p.giver.lang].title, html);
		}

		res.header("Content-Type", "application/json");
		res.send(JSON.stringify(success));
	});
}

if(config.secure)
{
	const https = require("https");
	const server = https.createServer(config.https, app);
	server.listen(config.port);
}
else
{
	const http = require("http");
	const server = http.createServer(app);
	server.listen(config.port);
}
