const AccountRepository = require("../repository/AccountRepository");
const { HttpBadRequest } = require("../utils/HttpError");

module.exports = class AccountService {
	#repository;

	constructor() {
		this.#repository = new AccountRepository();
	}

	async RegisterAccount(data) {
		try {
			const result = await this.#repository.RegisterAccount(data);

			const status = result[0][0].STATUS;
			const status_type = result[0][0].status_type;

			if (status_type === "bad_request") throw new HttpBadRequest(status, []);

			return status;
		} catch (err) {
			throw err;
		}
	}
};
