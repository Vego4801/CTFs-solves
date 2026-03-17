import {serve} from '@hono/node-server';
import {serveStatic} from '@hono/node-server/serve-static';
import {Hono} from 'hono';
import {readFileSync} from 'fs';

const flag = readFileSync('/flag.txt', 'utf8').trim();

const IsPalinDrome = (string) => {
	if (string.length < 1000) {
		return `Tootus Shortus -- ${string.length}`;
	}

	for (const i of Array(string.length).keys()) {
		const original = string[i];
		const reverse = string[string.length - i - 1];

		if (original !== reverse || typeof original !== 'string') {
			return `Notter Palindromer!!
string.length=${string.length}
i=${i}
original=${original}
reverse=${reverse}
equal=${original === reverse}
type=${typeof original}`;
		}
	}

	return null;
}

const app = new Hono();

app.get('/', serveStatic({root: '.'}));

app.post('/', async (c) => {
	const {palindrome} = await c.req.json();
	const error = IsPalinDrome(palindrome);
	if (error) {
		c.status(400);
		return c.text(error);
	}
	return c.text(`Hii Harry!!! ${flag}`);
});

app.port = 3000;

serve(app);