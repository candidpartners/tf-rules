const AWSMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-account-password-policy');
const debug = require('debug')('snitch/aws-security-group-does-not-allow-outbound.spec');

let AWSResult = {
    MinimumPasswordLength: 14,
    RequireSymbols: true,
    RequireNumbers: true,
    RequireUppercaseCharacters: true,
    RequireLowercaseCharacters: true,
    AllowUsersToChangePassword: true,
    ExpirePasswords: true,
    MaxPasswordAge: 90,
    PasswordReusePrevention: 10
};

let config = {
    MinimumPasswordLength: 14,
    RequireSymbols: true,
    RequireNumbers: true,
    RequireUppercaseCharacters: true,
    RequireLowercaseCharacters: true,
    AllowUsersToChangePassword: true,
    ExpirePasswords: true,
    MaxPasswordAge: 90,
    PasswordReusePrevention: 10
};

let goodInstance = {
    allow_users_to_change_password: true,
    max_password_age: 90,
    minimum_password_length: 14,
    password_reuse_prevention: 10,
    require_lowercase_characters: true,
    require_numbers: true,
    require_symbols: true,
    require_uppercase_characters: true
};

let badInstance = {
    max_password_age: 91,
    minimum_password_length: 5,
    password_reuse_prevention: 5,
    require_lowercase_characters: false,
    require_numbers: false,
    require_symbols: false,
    require_uppercase_characters: false
};

describe('aws-iam-account-password-policy conforms to CIS', function () {

    it("Recognizes a good password policy in a livecheck", async () => {
        let provider = new AWSMock();
        provider.Service("IAM","getAccountPasswordPolicy",{PasswordPolicy:AWSResult});
        const result = await rule.livecheck({config,provider});
        expect(result.valid).toBe('success');
    });

    it("Recognizes a bad password policy in a livecheck", async () => {
        let provider = new AWSMock();
        let serviceResult = {PasswordPolicy:AWSResult};
        serviceResult.PasswordPolicy.RequireNumbers = false;
        provider.Service("IAM","getAccountPasswordPolicy",serviceResult);
        const result = await rule.livecheck({config,provider});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('The account password policy is not compliant');
    });

    it("Recognizes a good password policy in a tfcheck", function () {
        const context = {config, instance: goodInstance, provider: {}};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });

    it("Recognizes a bad password policy in a tfcheck", function () {
        const context = {config, instance: badInstance, provider: {}};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
        expect(result.message).toHaveLength(8);
    })
});