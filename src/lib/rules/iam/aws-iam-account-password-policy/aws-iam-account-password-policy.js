'use strict';
const _ = require('lodash');
const debug = require('debug')('tfrules/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMAccountPasswordPolicy = {};

IAMAccountPasswordPolicy.uuid = "8acddea0-73b7-474a-9f65-5db172c5aefb";
IAMAccountPasswordPolicy.groupName = "IAM";

IAMAccountPasswordPolicy.docs = {
    description: "The IAM Account Password Policy must comply to CIS standards.",
    recommended: false
};

IAMAccountPasswordPolicy.schema = {type: 'boolean'}

IAMAccountPasswordPolicy.paths = {
    awsIAMAccountPasswordPolicy: 'aws_iam_account_password_policy'
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

module.exports = IAMAccountPasswordPolicy;

