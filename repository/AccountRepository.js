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

	SignIn(data) {
		const QUERY = `
            SELECT id, username, password FROM users WHERE username = ?
        `;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [data.username], (err, result) => {
				if (err) {
					reject(err);
				}
				resolve(result);
			});
		});
	}

	InsertUserTokens(data) {
		const QUERY = `
            INSERT INTO user_tokens (user_id, access_token, refresh_token) VALUES (?,?,?)
        `;

		return new Promise((resolve, reject) => {
			mysql.query(
				QUERY,
				[data.user_id, data.access_token, data.refresh_token],
				(err, result) => {
					if (err) {
						reject(err);
					}
					resolve(result);
				}
			);
		});
	}

	FindRefreshToken(refreshToken) {
		const QUERY = `
            SELECT refresh_token FROM user_tokens WHERE refresh_token = ?
        `;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [refreshToken], (err, result) => {
				if (err) {
					reject(err);
				}
				resolve(result);
			});
		});
	}

	DeleteUserTokensWithID(user_id) {
		const QUERY = `
            DELETE FROM user_tokens WHERE user_id =?
        `;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [user_id], (err, result) => {
				if (err) {
					reject(err);
				}
				resolve(result);
			});
		});
	}

	RefreshToken(data) {
		const QUERY = `
            UPDATE 
                user_tokens 
            SET 
                access_token = ?, 
                refresh_token = ?, 
                date_modified = NOW()
            WHERE 
                user_id = ? AND refresh_token = ?
        `;

		return new Promise((resolve, reject) => {
			mysql.query(
				QUERY,
				[
					data.new_access_token,
					data.new_refresh_token,
					data.user_id,
					data.refresh_token,
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
