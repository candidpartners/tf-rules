// @flow
const Papa = require('papaparse');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const MFAIsEnabledForIAMUsersWithConsolePassword = {};

MFAIsEnabledForIAMUsersWithConsolePassword.uuid = "0435cc47-21dc-45e3-a942-45dbef1cfb1b";
MFAIsEnabledForIAMUsersWithConsolePassword.groupName = "IAM";
MFAIsEnabledForIAMUsersWithConsolePassword.tags = [["CIS", "1.1.0", "1.2"]];
MFAIsEnabledForIAMUsersWithConsolePassword.config_triggers = ["AWS::IAM::User"];
MFAIsEnabledForIAMUsersWithConsolePassword.paths = {MFAIsEnabledForIAMUsersWithConsolePassword: "aws_iam_user"};
MFAIsEnabledForIAMUsersWithConsolePassword.docs = {
    description: 'All IAM users with a console password have MFA enabled.',
    recommended: false
};
MFAIsEnabledForIAMUsersWithConsolePassword.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


MFAIsEnabledForIAMUsersWithConsolePassword.livecheck = async function (context /*: Context */) /*: Promise<RuleResult>*/{

    // let IAM = new context.provider.IAM();
    //
    // // await IAM.generateCredentialReport().promise();
    // // let report = await IAM.getCredentialReport().promise();
    // //
    // // let content = report.Content.toString();
    let content=await context.services.IAM.GetIAMCredentialReport({provider: context.provider, additionalParams: {}});
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;
    let usersWithPasswordButNoMFA = data.filter(x => x.password_enabled == 'true' && x.mfa_active == 'false');

    return new RuleResult({
        valid: (usersWithPasswordButNoMFA.length > 0) ? "fail" : "success",
        message: "Console users must have MFA.",
        resources: data.map(x => {
            let password_enabled = x.password_enabled == 'true';
            let mfa_active = x.mfa_active == 'true';
            let hasPasswordWithoutMFA = password_enabled && !mfa_active;

            return new Resource({
                is_compliant: hasPasswordWithoutMFA ? false : true,
                resource_id: x.arn,
                resource_type: "AWS::IAM::User",
                message: hasPasswordWithoutMFA ? "has console access but no MFA enabled." : "has console access, and has MFA enabled."
            })
        })
    })
};

module.exports = MFAIsEnabledForIAMUsersWithConsolePassword;
