const jwt = require("jsonwebtoken");
const JsonWebToken = require("../utils/JsonWebToken");
const {
	HttpUnauthorized,
	HttpInternalServerError,
	HttpForbidden,
} = require("../utils/HttpError");
const logger = require("../config/winston");
const Crypto = require("../utils/Crypto");
const AccountRepository = require("../repository/AccountRepository");
module.exports = class TokenMiddleware {
	#repository;

	/**
	 * @constructor
	 */
	constructor() {
		this.#repository = new AccountRepository();
	}
	/**
	 * @method AccessTokenVerifier
	 */
	AccessTokenVerifier() {
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		return async (req, res, next) => {};
	}

	/**
	 * @method
	 */
	RefreshTokenVerifier() {
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */

		return async (req, res, next) => {
			try {
				const refreshToken = req.headers["authorization"]?.split(" ");

				if (!refreshToken || refreshToken[0] !== "Bearer")
					throw new HttpUnauthorized("INVALID_REFRESH_TOKEN");

				const refreshTokenFromDB = await this.#repository.FindRefreshToken(
					refreshToken[1]
				);

				if (refreshTokenFromDB.length < 1) {
					JsonWebToken.Verify(
						refreshToken[1],
						process.env.JWT_REFRESH_KEY,
						async (err, decode) => {
							if (err) throw new HttpForbidden("Forbidden", []);

							// Delete all access tokens associated with user
							logger.info("Deleting all access tokens");

							await this.#repository.DeleteUserTokensWithID(decode.data.id);
						}
					);

					throw new HttpForbidden("INVALID_REFRESH_TOKEN", []);
				}

				JsonWebToken.Verify(
					refreshToken[1],
					process.env.JWT_REFRESH_KEY,
					async (err, decode) => {
						if (err) {
							if (err instanceof jwt.TokenExpiredError)
								throw new HttpForbidden("INVALID_REFRESH_TOKEN", []);

							if (err instanceof jwt.JsonWebTokenError)
								throw new HttpForbidden("INVALID_REFRESH_TOKEN", []);

							throw new HttpInternalServerError("INTERNAL_SERVER_ERROR", []);
						}

						if (
							decode.aud !== process.env.JWT_AUDIENCE ||
							decode.iss !== process.env.JWT_ISSUER ||
							decode.typ !== process.env.JWT_TYPE ||
							decode.usr !== process.env.JWT_USER
						)
							throw new HttpUnauthorized("Unauthorized", []);

						req.id = decode.data.id;
						req.username = decode.data.username;
						req.refresh_token = refreshToken[1];
					}
				);
				next();
			} catch (err) {
				err.error_name = "INVALID_REFRESH_TOKEN_ERROR";
				next(err);
			}
		};
	}

	/**
	 * @method
	 */
	BasicTokenVerifier() {
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		return async (req, res, next) => {
			try {
				const authHeader = req.headers["authorization"]?.split(" ");

				if (!authHeader || authHeader[0] !== "Basic")
					throw new HttpUnauthorized("INVALID_BASIC_TOKEN");

				const base64Credentials = authHeader[1];
				const credentials = Buffer.from(base64Credentials, "base64").toString();
				const [username, password] = credentials.split(":");

				if (
					username !== process.env.BASIC_TOKEN_USERNAME ||
					password !== process.env.BASIC_TOKEN_PASSWORD
				)
					throw new HttpUnauthorized("INVALID_BASIC_TOKEN");

				next();
			} catch (err) {
				err.error_name = "INVALID_BASIC_TOKEN_ERROR";
				next(err);
			}
		};
	}
};
