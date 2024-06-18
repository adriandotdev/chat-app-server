const logger = require("../config/winston");
const TokenMiddleware = require("../middlewares/TokenMiddleware");

const { validationResult, body } = require("express-validator");

const { HttpUnprocessableEntity } = require("../utils/HttpError");
/**
 * @param {import('express').Express} app
 */
module.exports = (app) => {
	const tokenMiddleware = new TokenMiddleware();

	/**
	 * This function will be used by the express-validator for input validation,
	 * and to be attached to APIs middleware.
	 * @param {*} req
	 * @param {*} res
	 */
	function validate(req, res) {
		const ERRORS = validationResult(req);

		if (!ERRORS.isEmpty()) {
			throw new HttpUnprocessableEntity(
				"Unprocessable Entity",
				ERRORS.mapped()
			);
		}
	}

	app.post(
		"/api/v1/accounts/register",
		[
			tokenMiddleware.BasicTokenVerifier(),
			body("given_name")
				.notEmpty()
				.withMessage("Missing required property: given_name"),
			body("middle_name")
				.optional()
				.notEmpty()
				.withMessage("Missing required property: middle_name"),
			body("last_name")
				.notEmpty()
				.withMessage("Missing required property: last_name"),
			body("contact_number")
				.notEmpty()
				.withMessage("Missing required property: contact_number")
				.custom((value) => String(value).match(/^09\d{9}$/))
				.withMessage("Invalid contact number"),

			body("contact_email")
				.notEmpty()
				.withMessage("Missing required property: contact_email")
				.custom((value) =>
					String(value).match(
						/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
					)
				)
				.withMessage("Invalid contact email"),
			body("username")
				.notEmpty()
				.withMessage("Missing required property: username")
				.isLength({ min: 8 })
				.withMessage("Username must be at least 8 characters")
				.custom((value) => String(value).match(/^[a-zA-Z0-9_]+$/))
				.withMessage("Username must only contain alphanumeric characters"),
			body("password")
				.notEmpty()
				.withMessage("Missing required property: password")
				.isLength({ min: 8 })
				.withMessage("Password must be at least 8 characters")
				.custom((value) => String(value).match(/^[a-zA-Z0-9_]+$/))
				.withMessage("Password must only contain alphanumeric characters"),
			body("profile_picture")
				.notEmpty()
				.withMessage("Missing required property: profile_picture"),
		],

		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			try {
				logger.info({
					REGISTER_ACCOUNT_REQUEST: {
						data: { ...req.body },
						message: "SUCCESS",
					},
				});

				validate(req, res);

				logger.info({
					REGISTER_ACCOUNT_RESPONSE: {
						message: "SUCCESS",
					},
				});
				return res
					.status(200)
					.json({ status: 200, data: [], message: "Success" });
			} catch (err) {
				err.error_name = "REGISTER_ACCOUNT_ERROR";
				next(err);
			}
		}
	);

	app.use((err, req, res, next) => {
		logger.error({
			API_REQUEST_ERROR: {
				message: err.message,
				stack: err.stack.replace(/\\/g, "/"), // Include stack trace for debugging
				request: {
					method: req.method,
					url: req.url,
					code: err.status || 500,
				},
				data: err.data || [],
			},
		});

		const status = err.status || 500;
		const message = err.message || "Internal Server Error";

		res.status(status).json({
			status,
			data: err.data || [],
			message,
		});
	});
};
