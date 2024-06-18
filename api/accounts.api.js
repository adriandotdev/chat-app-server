const logger = require("../config/winston");
const TokenMiddleware = require("../middlewares/TokenMiddleware");
/**
 * @param {import('express').Express} app
 */
module.exports = (app) => {
	const tokenMiddleware = new TokenMiddleware();

	app.post(
		"/api/v1/accounts/register",
		[tokenMiddleware.BasicTokenVerifier()],

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
