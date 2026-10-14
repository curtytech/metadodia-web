(function (global) {
    "use strict";

    const SALT_ROUNDS = 12;
    const MAX_PASSWORD_BYTES = 72;

    global.hashPassword = function hashPassword(password) {
        if (typeof password !== "string" || password.length === 0) {
            return Promise.reject(new TypeError("A senha deve ser uma string não vazia."));
        }

        if (new TextEncoder().encode(password).length > MAX_PASSWORD_BYTES) {
            return Promise.reject(new RangeError("A senha não pode exceder 72 bytes em UTF-8."));
        }

        const bcrypt = global.dcodeIO && global.dcodeIO.bcrypt;
        if (!bcrypt) {
            return Promise.reject(new Error("Não foi possível carregar a biblioteca bcrypt."));
        }

        return new Promise((resolve, reject) => {
            bcrypt.hash(password, SALT_ROUNDS, (error, hash) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(hash);
            });
        });
    };

    global.comparePassword = function comparePassword(password, hash) {
        if (typeof password !== "string" || typeof hash !== "string") {
            return Promise.resolve(false);
        }

        const bcrypt = global.dcodeIO && global.dcodeIO.bcrypt;
        if (!bcrypt) {
            return Promise.reject(new Error("Não foi possível carregar a biblioteca bcrypt."));
        }

        return new Promise((resolve, reject) => {
            bcrypt.compare(password, hash, (error, matches) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(matches);
            });
        });
    };
})(window);