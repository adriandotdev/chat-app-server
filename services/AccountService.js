const AccountRepository = require("../repository/AccountRepository");
const { HttpBadRequest, HttpUnauthorized } = require("../utils/HttpError");

const bcrypt = require("bcrypt");
const JWT = require("../utils/JsonWebToken");
const { v4: uuidv4 } = require("uuid");

module.exports = class AccountService {
	#repository;

	constructor() {
		this.#repository = new AccountRepository();
	}

	async RegisterAccount(data) {
		try {
			const saltRound = 10;

			const hashedPassword = await bcrypt.hash(data.password, saltRound);

			const result = await this.#repository.RegisterAccount({
				...data,
				password: hashedPassword,
			});

			const status = result[0][0].STATUS;
			const status_type = result[0][0].status_type;

			if (status_type === "bad_request") throw new HttpBadRequest(status, []);

			return status;
		} catch (err) {
			throw err;
		}
	}

	async SignIn(data) {
		try {
			const result = await this.#repository.SignIn(data);

			if (!result.length) throw new HttpUnauthorized("INVALID_CREDENTIALS", []);

			const user = result[0];

			const isMatch = await bcrypt.compare(data.password, user.password);

			if (!isMatch) throw new HttpUnauthorized("INVALID_CREDENTIALS", []);

			const payload = { id: user.id, username: user.username };
			const accessTokenExpiration = Math.floor(Date.now() / 1000) + 60 * 15; // 15 mins
			const refreshTokenExpiration =
				Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30; // 1 month

			const accessToken = JWT.Sign(
				{
					data: payload,
					jti: uuidv4(),
					aud: "humble-chat-app",
					iss: "humble",
					iat: Math.floor(Date.now() / 1000),
					typ: "Bearer",
					exp: accessTokenExpiration,
					usr: "serv",
				},
				process.env.JWT_ACCESS_KEY
			);

			const refreshToken = JWT.Sign(
				{
					data: payload,
					jti: uuidv4(),
					aud: "humble-chat-app",
					iss: "humble",
					iat: Math.floor(Date.now() / 1000),
					typ: "Bearer",
					exp: refreshTokenExpiration,
					usr: "serv",
				},
				process.env.JWT_REFRESH_KEY
			);

			// Insert user tokens to db
			await this.#repository.InsertUserTokens({
				user_id: user.id,
				access_token: accessToken,
				refresh_token: refreshToken,
			});

			return { access_token: accessToken, refresh_token: refreshToken };
		} catch (err) {
			throw err;
		}
	}
};
