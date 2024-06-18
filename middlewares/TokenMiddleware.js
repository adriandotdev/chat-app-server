const jwt = require("jsonwebtoken");
const JsonWebToken = require("../utils/JsonWebToken");
const {
	HttpUnauthorized,
	HttpInternalServerError,
	HttpForbidden,
} = require("../utils/HttpError");
const logger = require("../config/winston");
const Crypto = require("../utils/Crypto");

module.exports = class TokenMiddleware {
	#repository;

	/**
	 * @constructor
	 */
	constructor() {}
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

		return async (req, res, next) => {};
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
