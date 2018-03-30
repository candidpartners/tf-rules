const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const HardwareMFAIsEnabledForRootAccount = {};

HardwareMFAIsEnabledForRootAccount.uuid = "ce94627d-c31b-412b-803b-51de836e0449";
HardwareMFAIsEnabledForRootAccount.groupName = "IAM";
HardwareMFAIsEnabledForRootAccount.tags = ["CIS | 1.1.0 | 1.14"];
HardwareMFAIsEnabledForRootAccount.config_triggers = ["AWS::IAM::User"];
HardwareMFAIsEnabledForRootAccount.paths = {MFAIsEnabledForIAMUsersWithConsolePassword: "aws_iam_user"};
HardwareMFAIsEnabledForRootAccount.docs = {
    description: 'The root account has hardware MFA enabled.',
    recommended: false
};
HardwareMFAIsEnabledForRootAccount.schema = { type : 'boolean' };


HardwareMFAIsEnabledForRootAccount.livecheck = co.wrap(function *( context ) {
    let IAM = new context.provider.IAM();

    yield IAM.generateCredentialReport().promise();
    let report1 = yield IAM.getCredentialReport().promise();

    let content = report1.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let rootUser1 = data.find(x => x.user === `<root_account>`);

    let report2 = yield IAM.listMFADevices().promise();
    let rootUser2;
    if (report2.MFADevices) {
        rootUser2 = report2.MFADevices.find(x => x.UserName == "<root_account>");
    }

    if(!rootUser2){
        return new RuleResult({
            valid: 'fail',
            message: "Root account does not have hardware MFA enabled.",
            noncompliant_resources: [new NonCompliantResource({
                resource_id: rootUser1.arn,
                resource_type: "AWS::IAM::User",
                message: "Root account does not have hardware MFA enabled."
            })]
        })
    }
    else {
        return new RuleResult({
            valid: 'success'
        })
    }
});

module.exports = HardwareMFAIsEnabledForRootAccount;