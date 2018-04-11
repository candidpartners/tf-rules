// @flow
const Papa = require('papaparse');
const {Resource,RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const MFAIsEnabledForRootAccount = {};

MFAIsEnabledForRootAccount.uuid = "ce94627d-c31b-412b-803b-51de836e0449";
MFAIsEnabledForRootAccount.groupName = "IAM";
MFAIsEnabledForRootAccount.tags = [["CIS", "1.1.0", "1.13"]];
MFAIsEnabledForRootAccount.config_triggers = ["AWS::IAM::User"];
MFAIsEnabledForRootAccount.paths = {MFAIsEnabledForIAMUsersWithConsolePassword: "aws_iam_user"};
MFAIsEnabledForRootAccount.docs = {
    description: 'The root account has MFA enabled.',
    recommended: false
};
MFAIsEnabledForRootAccount.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


MFAIsEnabledForRootAccount.livecheck = async function( context /*: Context */) /*: Promise<RuleResult> */ {

    let IAM = new context.provider.IAM();

    await IAM.generateCredentialReport().promise();
    let report = await IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let rootUser = data.find(x => x.user === `<root_account>`);

    let isInvalid = (rootUser.mfa_active === "false")
    return new RuleResult({
        valid: isInvalid ? "fail" : "success",
        message: "Root account must have MFA enabled",
        resources: [{
            is_compliant: isInvalid ? false : true,
            resource_id: rootUser.arn,
            resource_type: "AWS::IAM::User",
            message: isInvalid ? "does not have MFA enabled." : "has MFA enabled"
        }]
    });
};

module.exports = MFAIsEnabledForRootAccount;