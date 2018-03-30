const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const MFAIsEnabledForRootAccount = {};

MFAIsEnabledForRootAccount.uuid = "ce94627d-c31b-412b-803b-51de836e0449";
MFAIsEnabledForRootAccount.groupName = "IAM";
MFAIsEnabledForRootAccount.tags = ["CIS | 1.1.0 | 1.13"];
MFAIsEnabledForRootAccount.config_triggers = ["AWS::IAM::User"];
MFAIsEnabledForRootAccount.paths = {MFAIsEnabledForIAMUsersWithConsolePassword: "aws_iam_user"};
MFAIsEnabledForRootAccount.docs = {
    description: 'The root account has MFA enabled.',
    recommended: false
};
MFAIsEnabledForRootAccount.schema = { type : 'boolean' };


MFAIsEnabledForRootAccount.livecheck = co.wrap(function *( context ) {

    let IAM = new context.provider.IAM();

    yield IAM.generateCredentialReport().promise();
    let report = yield IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let rootUser = data.find(x => x.user === `<root_account>`);

    if(rootUser.mfa_active === "false"){
        return new RuleResult({
            valid: 'fail',
            message: "Root account does not have MFA enabled.",
            noncompliant_resources: new NonCompliantResource({
                resource_id: rootUser.arn,
                resource_type: "AWS::IAM::User",
                message: "Root account does not have MFA enabled."
            })
        })
    }
    else {
        return new RuleResult({
            valid: 'success'
        })
    }
});

module.exports = MFAIsEnabledForRootAccount;