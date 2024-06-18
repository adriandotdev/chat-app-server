const mysql = require("../database/mysql");

module.exports = class AccountRepository {
	#GenerateQuestionMarks(numberOfQueries) {
		return Array.from({ length: numberOfQueries }, () => "?,").join("");
	}

	RegisterAccount(data) {
		const parameterizedQuery = this.#GenerateQuestionMarks(8);
		const QUERY = `CALL SP_USER_REGISTER_ACCOUNT(${parameterizedQuery.slice(
			0,
			parameterizedQuery.length - 1
		)})`;

		return new Promise((resolve, reject) => {
			mysql.query(
				QUERY,
				[
					data.given_name,
					data.middle_name,
					data.last_name,
					data.contact_number,
					data.contact_email,
					data.username,
					data.password,
					data.profile_picture,
				],
				(err, result) => {
					if (err) {
						reject(err);
					}
					resolve(result);
				}
			);
		});
	}
};
