const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-password-policy-conforms');

let _AWS = new AWSPromiseMock();
let content = {
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
};
_AWS.Service("IAM", "getAccountPasswordPolicy", content);

describe("iam_password_policy_conforms", () => {
    describe("Can recognize a success", () => {
        test("Succeeds if no params are checked", async () => {
            let result = await rule.livecheck({provider: _AWS, params: {}});
            expect(result.valid).toBe('success');
        });

        test("Succeeds if params are checked", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: false,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: false,
                    HardExpiry: false
                }
            });

            expect(result.valid).toBe('success');
        })
    });

    describe("Can recognize a failure", () => {

        test("Fails if invalid MinimumPasswordLength", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 5,
                    RequireSymbols: false,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: false,
                    HardExpiry: false
                }
            });
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireSymbols", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: true,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: false,
                    HardExpiry: false
                }
            });
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireNumbers", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: false,
                    RequireNumbers: true,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: false,
                    HardExpiry: false
                }
            });
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireUppercaseCharacters", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: false,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: true,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: false,
                    HardExpiry: false
                }
            });
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid RequireLowercaseCharacters", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: false,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: true,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: false,
                    HardExpiry: false
                }
            });
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid AllowUsersToChangePassword", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: false,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: false,
                    ExpirePasswords: false,
                    HardExpiry: false
                }
            });
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid ExpirePasswords", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: false,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: true,
                    HardExpiry: false
                }
            });
            expect(result.valid).toBe('fail');
        });

        test("Fails if invalid HardExpiry", async () => {
            let result = await rule.livecheck({
                provider: _AWS, params: {
                    MinimumPasswordLength: 6,
                    RequireSymbols: false,
                    RequireNumbers: false,
                    RequireUppercaseCharacters: false,
                    RequireLowercaseCharacters: false,
                    AllowUsersToChangePassword: true,
                    ExpirePasswords: false,
                    HardExpiry: true
                }
            });
            expect(result.valid).toBe('fail');
        });
    })
});
