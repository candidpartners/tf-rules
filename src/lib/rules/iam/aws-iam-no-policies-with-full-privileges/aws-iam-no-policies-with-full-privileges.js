'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMNoPoliciesWithFullPrivileges = {};

IAMNoPoliciesWithFullPrivileges.uuid = "526bb8b8-5e04-4d49-9f2a-869a3a5912c7";
IAMNoPoliciesWithFullPrivileges.groupName = "IAM";
IAMNoPoliciesWithFullPrivileges.tags = [["CIS", "1.1.0", "1.24"]];
IAMNoPoliciesWithFullPrivileges.config_triggers = ["AWS::IAM::Policy"];
IAMNoPoliciesWithFullPrivileges.paths = {IAMNoPoliciesWithFullPrivileges: "aws_iam_policy"};
IAMNoPoliciesWithFullPrivileges.docs = {description: 'No IAM polcies should exist that allow full administrative privileges.', recommended: true};
IAMNoPoliciesWithFullPrivileges.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        }
    }
};


IAMNoPoliciesWithFullPrivileges.livecheck = async function (context) {
    let {config, provider} = context;

    let iam = new provider.IAM();
    let policies = await iam.listPolicies().promise();

    let badPolicies = [];

    for (let i = 0; i < policies.Policies.length; i++) {
        let policyVersion = await iam.getPolicyVersion({PolicyArn: policies.Policies[i].Arn, VersionId: policies.Policies[i].DefaultVersionId}).promise();

        let document = decodeURIComponent(policyVersion.PolicyVersion.Document);
        if (document.includes('"Effect": "Allow"') && document.includes('"Action": "*"')) {
            badPolicies.push(policies.Policies[i].PolicyName)
        }
    }

    return new RuleResult({
        valid: (badPolicies.length > 0) ? "fail" : "success",
        message: "No IAM policies should allow full administrative privileges.",
        resources: policies.Policies.map(policy => {
            return new Resource({
                is_compliant: (badPolicies.includes(policy.PolicyName)) ? false : true,
                resource_id: policy.PolicyName,
                resource_type: "AWS::IAM::Policy",
                message: (badPolicies.includes(policy.PolicyName)) ? "allows full administrative privileges." : "does not allow full administrative privileges."
            })
        })
    });
};

module.exports = IAMNoPoliciesWithFullPrivileges;