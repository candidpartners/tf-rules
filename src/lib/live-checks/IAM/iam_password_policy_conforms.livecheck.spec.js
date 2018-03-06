const AWS = require('aws-sdk');
const rule = require('./iam_password_policy_conforms.livecheck');

const _AWS = {
    IAM: class IAM {
        getAccountPasswordPolicy() {
            return {
                promise() {
                    return Promise.resolve({
                        PasswordPolicy: {
                            MinimumPasswordLength: 6,
                            RequireSymbols: false,
                            RequireNumbers: false,
                            RequireUppercaseCharacters: false,
                            RequireLowercaseCharacters: false,
                            AllowUsersToChangePassword: true,
                            ExpirePasswords: false,
                            HardExpiry: false
                        }
                    })
                }
            }
        }
    }
};

describe("iam_password_policy_conforms", () => {
    describe("Can recognize a success", () => {
        test("Succeeds if no params are checked", async () => {
            let result = await rule.validate({provider: _AWS, params: {}});
            expect(result.valid).toBe('success');
        });

        test("Succeeds if params are checked", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                MinimumPasswordLength: 6,
                RequireSymbols: false,
                RequireNumbers: false,
                RequireUppercaseCharacters: false,
                RequireLowercaseCharacters: false,
                AllowUsersToChangePassword: true,
                ExpirePasswords: false,
                HardExpiry: false
            }});

            expect(result.valid).toBe('success');
        })
    });

    describe("Can recognize a failure", () => {

        test("Fails if invalid MinimumPasswordLength", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                MinimumPasswordLength: 5,
            }});
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireSymbols", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                RequireSymbols: true,
            }});
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireNumbers", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                RequireNumbers: true,
            }});
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireUppercaseCharacters", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                RequireUppercaseCharacters: true,
            }});
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireLowercaseCharacters", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                RequireLowercaseCharacters: true,
            }});
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid AllowUsersToChangePassword", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                AllowUsersToChangePassword: false,
            }});
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid ExpirePasswords", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                ExpirePasswords: true,
            }});
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid HardExpiry", async () => {
            let result = await rule.validate({provider: _AWS, params: {
                HardExpiry: true,
            }});
            expect(result.valid).toBe('fail');
        });
    })
});
