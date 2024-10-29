import { vValidator } from "@hono/valibot-validator";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { number, object, parse, string } from "valibot";

type Bindings = {
	CLIENT_ID: string;
	CLIENT_SECRET: string;
	REDIRECT_URI: string;
};

const GetTokenSchema = object({
	code: string(),
	redirect_uri: string(),
});

const TokenResponseSchema = object({
	access_token: string(),
	token_type: string(),
	scope: string(),
	created_at: number(),
});

const DeleteTokenSchema = object({
	token: string(),
});

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", cors({ origin: "*" }));

app.get("/token", vValidator("query", GetTokenSchema), async (c) => {
	const code = c.req.valid("query").code;
	const redirectUri = c.req.valid("query").redirect_uri;

	const clientId = c.env.CLIENT_ID;
	if (!clientId) {
		throw new Error("CLIENT_ID is not set");
	}
	const clientSecret = c.env.CLIENT_SECRET;
	if (!clientSecret) {
		throw new Error("CLIENT_SECRET is not set");
	}

	const params = new URLSearchParams({
		client_id: clientId,
		client_secret: clientSecret,
		grant_type: "authorization_code",
		redirect_uri: redirectUri,
		code,
	});
	const paramsStr = params.toString();

	const res = await fetch(`https://annict.com/oauth/token?${paramsStr}`, {
		method: "POST",
	});
	if (!res.ok) {
		console.error(await res.json());
		return c.json({ message: "Failed to generate token" }, 400);
	}

	const json = await res.json();
	const validJson = parse(TokenResponseSchema, json);
	return c.json(validJson);
});

app.delete("/token", vValidator("query", DeleteTokenSchema), async (c) => {
	const token = c.req.valid("query").token;

	const clientId = c.env.CLIENT_ID;
	if (!clientId) {
		throw new Error("CLIENT_ID is not set");
	}
	const clientSecret = c.env.CLIENT_SECRET;
	if (!clientSecret) {
		throw new Error("CLIENT_SECRET is not set");
	}

	const params = new URLSearchParams({
		client_id: clientId,
		client_secret: clientSecret,
		token,
	});
	const paramsStr = params.toString();

	const res = await fetch(`https://annict.com/oauth/revoke?${paramsStr}`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});
	if (!res.ok) {
		console.error(res);
		return c.json({ message: "Failed to revoke token" }, 400);
	}

	return c.json({ message: "Token revoked" });
});

export default app;
