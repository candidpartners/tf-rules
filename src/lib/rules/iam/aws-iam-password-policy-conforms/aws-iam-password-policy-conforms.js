const co = require('co');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAM_PASSWORD_POLICY_CONFORMS = {};

IAM_PASSWORD_POLICY_CONFORMS.docs = {
    description: 'Checks that the IAM policy conforms',
    recommended: false
};

IAM_PASSWORD_POLICY_CONFORMS.tags = ["CIS"];

IAM_PASSWORD_POLICY_CONFORMS.schema = {type: 'boolean'};

IAM_PASSWORD_POLICY_CONFORMS.livecheck = co.wrap(function* (context) {
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
    } = context.params;


    try {
        const result = yield IAM.getAccountPasswordPolicy().promise();
        const {PasswordPolicy} = result;

        let errors = [];

        if (MinimumPasswordLength !== undefined)
            if (PasswordPolicy.MinimumPasswordLength != MinimumPasswordLength)
                errors.push(`Password policy needs MinimumPasswordLength of ${MinimumPasswordLength}`);

        if (RequireSymbols !== undefined)
            if (PasswordPolicy.RequireSymbols != RequireSymbols)
                errors.push(`Password policy needs RequireSymbols = ${RequireSymbols}`);

        if (RequireNumbers !== undefined)
            if (PasswordPolicy.RequireNumbers != RequireNumbers)
                errors.push(`Password policy needs RequireNumbers = ${RequireNumbers}`);

        if (RequireUppercaseCharacters !== undefined)
            if (PasswordPolicy.RequireUppercaseCharacters != RequireUppercaseCharacters)
                errors.push(`Password policy needs RequireUppercaseCharacters = ${RequireUppercaseCharacters}`);

        if (RequireLowercaseCharacters !== undefined)
            if (PasswordPolicy.RequireLowercaseCharacters != RequireLowercaseCharacters)
                errors.push(`Password policy needs RequireLowercaseCharacters = ${RequireLowercaseCharacters}`);

        if (AllowUsersToChangePassword !== undefined)
            if (PasswordPolicy.AllowUsersToChangePassword != AllowUsersToChangePassword)
                errors.push(`Password policy needs AllowUsersToChangePassword = ${AllowUsersToChangePassword}`);

        if (ExpirePasswords !== undefined)
            if (PasswordPolicy.ExpirePasswords != ExpirePasswords)
                errors.push(`Password policy needs ExpirePasswords = ${ExpirePasswords}`);

        if (HardExpiry !== undefined)
            if (PasswordPolicy.HardExpiry != HardExpiry)
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

module.exports = IAM_PASSWORD_POLICY_CONFORMS;
