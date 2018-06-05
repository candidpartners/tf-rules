// @flow
const Papa = require('papaparse');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const HardwareMFAIsEnabledForRootAccount = {};

HardwareMFAIsEnabledForRootAccount.uuid = "32243a91-ff70-4366-83fb-293bcfda46b0";
HardwareMFAIsEnabledForRootAccount.groupName = "IAM";
HardwareMFAIsEnabledForRootAccount.tags = [["CIS", "1.1.0", "1.14"]];
HardwareMFAIsEnabledForRootAccount.config_triggers = ["AWS::IAM::User"];
HardwareMFAIsEnabledForRootAccount.paths = {MFAIsEnabledForIAMUsersWithConsolePassword: "aws_iam_user"};
HardwareMFAIsEnabledForRootAccount.docs = {
    description: 'The root account has hardware MFA enabled.',
    recommended: false
};
HardwareMFAIsEnabledForRootAccount.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


HardwareMFAIsEnabledForRootAccount.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {

    // await IAM.generateCredentialReport().promise();
    // let report1 = await IAM.getCredentialReport().promise();

    let content=await context.services.IAM.GetIAMCredentialReport({provider: context.provider, additionalParams: {}});
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let rootUser1 = data.find(x => x.user === `<root_account>`);

    let virtualRoot = undefined;
    if (rootUser1.mfa_active === "true") {
        const IAM = new context.provider.IAM();
        let virtualReport = await IAM.listVirtualMFADevices().promise();
        if (virtualReport.VirtualMFADevices) {
            virtualRoot = virtualReport.VirtualMFADevices.find(x => x.SerialNumber.includes("mfa/root-account-mfa-device"));
        }
    }

    if (virtualRoot !== undefined) {
        return new RuleResult({
            valid: 'fail',
            message: "Root account does not have hardware MFA enabled.",
            resources: [new Resource({
                is_compliant: false,
                resource_id: rootUser1.arn,
                resource_type: "AWS::IAM::User",
                message: "has virtual MFA enabled; hardware MFA is required for compliance."
            })]
        })
    }
    else if (rootUser1.mfa_active === "false" && virtualRoot === undefined) {
        return new RuleResult({
            valid: 'fail',
            message: "Root account does not have hardware MFA enabled.",
            resources: [new Resource({
                is_compliant: false,
                resource_id: rootUser1.arn,
                resource_type: "AWS::IAM::User",
                message: "does not have virtual or hardware MFA enabled."
            })]
        })
    }
    else {
        return new RuleResult({
            valid: 'success',
            message: "Root account has hardware MFA enabled",
            resources: [
                new Resource({
                    is_compliant: true,
                    resource_id: rootUser1.arn,
                    resource_type: "AWS::IAM::User",
                    message: "has hardware MFA enabled."
                })
            ]
        })
    }
};

module.exports = HardwareMFAIsEnabledForRootAccount;