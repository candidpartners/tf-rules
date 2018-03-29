const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const MFAIsEnabledForIAMUsersWithConsolePassword = {};

MFAIsEnabledForIAMUsersWithConsolePassword.docs = {
    description: 'Checks that all IAM users with a console password have MFA enabled',
    recommended: false
};

MFAIsEnabledForIAMUsersWithConsolePassword.tags = ["CIS | 1.1.0 | 1.2"];

MFAIsEnabledForIAMUsersWithConsolePassword.schema = { type : 'boolean' };

MFAIsEnabledForIAMUsersWithConsolePassword.config_triggers = ["AWS::IAM::User"];

MFAIsEnabledForIAMUsersWithConsolePassword.livecheck = co.wrap(function *( context ) {

    let IAM = new context.provider.IAM();

    yield IAM.generateCredentialReport().promise();
    let report = yield IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;
    let usersWithPasswordButNoMFA = data.filter(x => x.password_enabled == 'true' && x.mfa_active == 'false');

    if(usersWithPasswordButNoMFA.length > 0){
        return new RuleResult({
            valid: 'fail',
            message: "Some console users don't have MFA.",
            noncompliant_resources: usersWithPasswordButNoMFA.map(x => new NonCompliantResource({
                resource_id: x.arn,
                resource_type: "AWS::IAM::User",
                message: "Console user does not have MFA"
            }))
        })
    }
    else if (usersWithPasswordButNoMFA.length == 0){
        return new RuleResult({
            valid: 'success'
        })
    }
});

module.exports = MFAIsEnabledForIAMUsersWithConsolePassword;
