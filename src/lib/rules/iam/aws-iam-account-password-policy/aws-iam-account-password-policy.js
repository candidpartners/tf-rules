'use strict';
const co = require('co');
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');
const {RuleResult,NonCompliantResource} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMAccountPasswordPolicy = {};

IAMAccountPasswordPolicy.uuid = "8acddea0-73b7-474a-9f65-5db172c5aefb";
IAMAccountPasswordPolicy.groupName = "IAM";
IAMAccountPasswordPolicy.tags = [
    ["CIS", "1.1.0", "1.5"],
    ["CIS", "1.1.0", "1.6"],
    ["CIS", "1.1.0", "1.7"],
    ["CIS", "1.1.0", "1.8"],
    ["CIS", "1.1.0", "1.9"],
    ["CIS", "1.1.0", "1.10"],
    ["CIS", "1.1.0", "1.11"]
];
IAMAccountPasswordPolicy.config_triggers = ["AWS::::Account"];
IAMAccountPasswordPolicy.paths = {IAMAccountPasswordPolicy: 'aws_iam_account_password_policy'};
IAMAccountPasswordPolicy.docs = {
    description: "The IAM account password policy complies to CIS standards.",
    recommended: false
};
IAMAccountPasswordPolicy.schema = {
    type: 'object',
    required: [
        "MinimumPasswordLength",
        "MaxPasswordAge",
        "PasswordReusePrevention"
    ],
    properties: {
        MinimumPasswordLength: {type: "number"},
        MaxPasswordAge: {type: "number"},
        RequireSymbols: {type: "boolean"},
        RequireNumbers: {type: "boolean"},
        RequireUppercaseCharacters: {type: "boolean"},
        RequireLowercaseCharacters: {type: "boolean"},
        AllowUsersToChangePassword: {type: "boolean"},
        ExpirePasswords: {type: "boolean"},
        PasswordReusePrevention: {type: "number"}
    },
};


IAMAccountPasswordPolicy.livecheck = co.wrap(function* (context) {
    const IAM = new context.provider.IAM();
    let config = context.config;

    try{
        const result = yield IAM.getAccountPasswordPolicy().promise();
        const {PasswordPolicy} = result;
        // console.log(PasswordPolicy,config);
        let errors =_.map(config, (value,key) => {
            let PasswordPolicyValue = PasswordPolicy[key];
            if(PasswordPolicyValue !== value)
                return `Password Policy does not match config for ${key}`
        }).filter(x => x);

        if(errors.length){
            return new RuleResult({
                valid: "fail",
                message: "The account password policy is not compliant",
                noncompliant_resources: [
                    new NonCompliantResource({
                        resource_id: "Password Policy",
                        resource_type:"AWS::::Account",
                        message: "The password policy does not conform to the config. " + errors.join('\n')
                    })
                ]})
        }
        else{
            return new RuleResult({
                valid: "success"
            })
        }

    } catch(error){
        return {valid: 'fail', message: error.message}
    }
});

IAMAccountPasswordPolicy.validate = function (context) {
    let instance = context.instance;
    const {
        MinimumPasswordLength,
        MaxPasswordAge,
        RequireSymbols,
        RequireNumbers,
        RequireUppercaseCharacters,
        RequireLowercaseCharacters,
        AllowUsersToChangePassword,
        ExpirePasswords, //Terraform derives from max password age
        PasswordReusePrevention
    } = context.config;

    let possibleErrors = [
        {
            error: "Password Policy does not match config for RequireUppercaseCharacters",
            isValid: (instance) => _.get(instance, 'require_uppercase_characters', false) === RequireUppercaseCharacters
        },
        {
            error: "Password Policy does not match config for RequireLowercaseCharacters",
            isValid: (instance) => _.get(instance, 'require_lowercase_characters', false) === RequireLowercaseCharacters
        },
        {
            error: "Password Policy does not match config for RequireSymbols",
            isValid: (instance) => _.get(instance, 'require_symbols', false) === RequireSymbols
        },
        {
            error: "Password Policy does not match config for RequireNumbers",
            isValid: (instance) => _.get(instance, 'require_numbers', false) === RequireNumbers
        },
        {
            error: "Password Policy does not match config for MinimumPasswordLength",
            isValid: (instance) => _.get(instance, 'minimum_password_length', 0) === MinimumPasswordLength
        },
        {
            error: "Password Policy does not match config for PasswordReusePrevention",
            isValid: (instance) => _.get(instance, 'password_reuse_prevention', 0) === PasswordReusePrevention
        },
        {
            error: "Password Policy does not match config for MaxPasswordAge",
            isValid: (instance) => _.get(instance, 'max_password_age', undefined) === MaxPasswordAge
        },
        {
            error: "Password Policy does not match config for AllowUsersToChangePassword",
            isValid: (instance) => _.get(instance, 'allow_users_to_change_password', undefined) === AllowUsersToChangePassword
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

