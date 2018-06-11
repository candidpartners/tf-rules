'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMPoliciesAreLeastPrivileged = {};

IAMPoliciesAreLeastPrivileged.uuid = "526bb8b8-5e04-4d49-9f2a-869a3a5912c7";
IAMPoliciesAreLeastPrivileged.groupName = "IAM";
IAMPoliciesAreLeastPrivileged.tags = [["CIS", "1.1.0", "1.24"]];
IAMPoliciesAreLeastPrivileged.config_triggers = ["AWS::IAM::Policy"];
IAMPoliciesAreLeastPrivileged.paths = {IAMNoPoliciesWithFullPrivileges: "aws_iam_policy"};
IAMPoliciesAreLeastPrivileged.docs = {description: 'IAM policies should follow a least-privileged model.', recommended: true};
IAMPoliciesAreLeastPrivileged.schema = {
    type: 'object',
    properties: {}
};


IAMPoliciesAreLeastPrivileged.livecheck = async function (context) {
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
        message: "IAM policies should follow a least-privileged model.",
        resources: policies.Policies.map(policy => {
            return new Resource({
                is_compliant: (badPolicies.includes(policy.PolicyName)) ? false : true,
                resource_id: policy.PolicyName,
                resource_type: "AWS::IAM::Policy",
                message: (badPolicies.includes(policy.PolicyName)) ? "allows full privileges." : "only allows specified privileges."
            })
        })
    });
};

module.exports = IAMPoliciesAreLeastPrivileged;