const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const MFAIsEnabledForIAMUsersWithConsolePassword = {};

MFAIsEnabledForIAMUsersWithConsolePassword.uuid = "0435cc47-21dc-45e3-a942-45dbef1cfb1b";
MFAIsEnabledForIAMUsersWithConsolePassword.groupName = "IAM";
MFAIsEnabledForIAMUsersWithConsolePassword.tags = ["CIS | 1.1.0 | 1.2"];
MFAIsEnabledForIAMUsersWithConsolePassword.config_triggers = ["AWS::IAM::User"];
MFAIsEnabledForIAMUsersWithConsolePassword.paths = {MFAIsEnabledForIAMUsersWithConsolePassword: "aws_iam_user"};
MFAIsEnabledForIAMUsersWithConsolePassword.docs = {
    description: 'All IAM users with a console password have MFA enabled.',
    recommended: false
};
MFAIsEnabledForIAMUsersWithConsolePassword.schema = { type : 'boolean', default: true };


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
            message: "Some console users don't have MFA enabled.",
            noncompliant_resources: usersWithPasswordButNoMFA.map(x => new NonCompliantResource({
                resource_id: x.arn,
                resource_type: "AWS::IAM::User",
                message: "does not have MFA enabled."
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
