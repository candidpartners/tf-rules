'use strict';
const co = require('co');
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMAccountPasswordPolicy = {};

IAMAccountPasswordPolicy.uuid = "8acddea0-73b7-474a-9f65-5db172c5aefb";
IAMAccountPasswordPolicy.groupName = "IAM";
IAMAccountPasswordPolicy.tags = [
    "CIS | 1.1.0 | 1.5",
    "CIS | 1.1.0 | 1.6",
    "CIS | 1.1.0 | 1.7",
    "CIS | 1.1.0 | 1.8",
    "CIS | 1.1.0 | 1.9",
    "CIS | 1.1.0 | 1.10",
    "CIS | 1.1.0 | 1.11"
];
IAMAccountPasswordPolicy.config_triggers = ["AWS::::Account"];
IAMAccountPasswordPolicy.paths = {IAMAccountPasswordPolicy: 'aws_iam_account_password_policy'};
IAMAccountPasswordPolicy.docs = {
    description: "The IAM account password policy complies to CIS standards.",
    recommended: false
};
IAMAccountPasswordPolicy.schema = {
    type: 'array',
    entries: [
        {type: 'number'},
        {type: 'bool'},
        {type: 'bool'},
        {type: 'bool'},
        {type: 'bool'},
        {type: 'bool'},
        {type: 'bool'},
        {type: 'bool'}
    ]
};

IAMAccountPasswordPolicy.validate = function (context) {
    let instance = context.instance;

    let possibleErrors = [
        {
            error: "CIS 1.5 - Policy should require an uppercase letter.",
            isValid: (instance) => _.get(instance, 'require_uppercase_characters', false)
        },
        {
            error: "CIS 1.6 - Policy should require a lowercase letter.",
            isValid: (instance) => _.get(instance, 'require_lowercase_characters', false)
        },
        {
            error: "CIS 1.7 - Policy should require a symbol",
            isValid: (instance) => _.get(instance, 'require_symbols', false)
        },
        {
            error: "CIS 1.8 - Policy should require a number",
            isValid: (instance) => _.get(instance, 'require_numbers', false)
        },
        {
            error: "CIS 1.9 - Policy should require a length of 14 or greater.",
            isValid: (instance) => _.get(instance, 'minimum_password_length', 0) >= 14
        },
        {
            error: "CIS 1.10 - Policy should prevent password reuse.",
            isValid: (instance) => _.get(instance, 'password_reuse_prevention', 0) === 1
        },
        {
            error: "CIS 1.11 - Policy should expire passwords within 90 days.",
            isValid: (instance) => _.get(instance, 'max_password_age', 100) <= 90
        },
    ];

    let errors = possibleErrors
        .filter(x => x.isValid(instance) == false)
        .map(x => x.error)

    return {
        valid: (errors.length === 0) ? 'success' : 'fail',
        message: (errors.length === 0) ? undefined : errors
    }
};

IAMAccountPasswordPolicy.livecheck = co.wrap(function* (context) {
    const IAM = new context.provider.IAM();
    const {
        MinimumPasswordLength,
        RequireSymbols,
        RequireNumbers,
        RequireUppercaseCharacters,
        RequireLowercaseCharacters,
        AllowUsersToChangePassword,
        ExpirePasswords,
        HardExpiry
    } = context.config;


    try {
        const result = yield IAM.getAccountPasswordPolicy().promise();
        const {PasswordPolicy} = result;

        let errors = [];

        if (MinimumPasswordLength !== undefined)
            if (PasswordPolicy.MinimumPasswordLength !== MinimumPasswordLength)
                errors.push(`Password policy needs MinimumPasswordLength of ${MinimumPasswordLength}`);

        if (RequireSymbols !== undefined)
            if (PasswordPolicy.RequireSymbols !== RequireSymbols)
                errors.push(`Password policy needs RequireSymbols = ${RequireSymbols}`);

        if (RequireNumbers !== undefined)
            if (PasswordPolicy.RequireNumbers !== RequireNumbers)
                errors.push(`Password policy needs RequireNumbers = ${RequireNumbers}`);

        if (RequireUppercaseCharacters !== undefined)
            if (PasswordPolicy.RequireUppercaseCharacters !== RequireUppercaseCharacters)
                errors.push(`Password policy needs RequireUppercaseCharacters = ${RequireUppercaseCharacters}`);

        if (RequireLowercaseCharacters !== undefined)
            if (PasswordPolicy.RequireLowercaseCharacters !== RequireLowercaseCharacters)
                errors.push(`Password policy needs RequireLowercaseCharacters = ${RequireLowercaseCharacters}`);

        if (AllowUsersToChangePassword !== undefined)
            if (PasswordPolicy.AllowUsersToChangePassword !== AllowUsersToChangePassword)
                errors.push(`Password policy needs AllowUsersToChangePassword = ${AllowUsersToChangePassword}`);

        if (ExpirePasswords !== undefined)
            if (PasswordPolicy.ExpirePasswords !== ExpirePasswords)
                errors.push(`Password policy needs ExpirePasswords = ${ExpirePasswords}`);

        if (HardExpiry !== undefined)
            if (PasswordPolicy.HardExpiry !== HardExpiry)
                errors.push(`Password policy needs HardExpiry = ${HardExpiry}`);

        if (errors.length) {
            return {valid: 'fail', message: errors.join('\n')}
        }
        else {
            return {valid: 'success'}
        }

    } catch (err) {
        return {valid: 'fail', message: err.message}
    }
});

module.exports = IAMAccountPasswordPolicy;

