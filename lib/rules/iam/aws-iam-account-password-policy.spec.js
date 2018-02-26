const AWS = require('aws-stub');
const rule = require('./aws-iam-account-password-policy');
const debug = require('debug')('tfrules/aws-security-group-does-not-allow-outbound.spec');

let provider = {};

let goodInstance = {
    allow_users_to_change_password: true,
    max_password_age: 90,
    minimum_password_length: 14,
    password_reuse_prevention: 1,
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
    it("Recognizes a good password policy", function () {
        const context = {config: {},instance:goodInstance, provider};
        const result = rule.validate(context);
        console.log(result);
        expect(result.valid).toBe('success');
    });

    it("Recognizes a bad password policy", function (){
        const context = {config: {},instance: badInstance, provider};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
        expect(result.message).toHaveLength(7);
    })
});