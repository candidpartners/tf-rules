'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMPoliciesHaveRequestedRegion = {};

IAMPoliciesHaveRequestedRegion.uuid = "0f5358c2-35bc-4dbb-8750-ffdc53d58423";
IAMPoliciesHaveRequestedRegion.groupName = "IAM";
IAMPoliciesHaveRequestedRegion.tags = [["Candid", "1.0", "16"]];
IAMPoliciesHaveRequestedRegion.config_triggers = ["AWS::IAM::Policy"];
IAMPoliciesHaveRequestedRegion.paths = {IAMPoliciesHaveRequestedRegion: "aws_iam_policy"};
IAMPoliciesHaveRequestedRegion.docs = {description: 'All IAM policies should have a RequestedRegion condition.', recommended: true};
IAMPoliciesHaveRequestedRegion.schema = {
    type: 'object',
    properties: {}
};


IAMPoliciesHaveRequestedRegion.livecheck = async function (context) {
    let {config, provider} = context;

    let iam = new provider.IAM();
    let policies = await iam.listPolicies().promise();
    let badPolicies = [];
    let requested_regions = [];

    for (let i = 0; i < policies.Policies.length; i++) {
        let policyVersion = await iam.getPolicyVersion({PolicyArn: policies.Policies[i].Arn, VersionId: policies.Policies[i].DefaultVersionId}).promise();
        let document = decodeURIComponent(policyVersion.PolicyVersion.Document);
        if (!document.includes('"aws:RequestedRegion":')) {
            badPolicies.push(policies.Policies[i].PolicyName);
        }
        else {
            let requested_region = (document.split('"aws:RequestedRegion": ')[1]).split('\n')[0];
            requested_regions.push({policy: policies.Policies[i].Arn, region: requested_region})
        }
    }


    return new RuleResult({
        valid: (badPolicies.length > 0) ? "fail" : "success",
        message: "All IAM policies should have a RequestedRegion condition.",
        resources: policies.Policies.map(policy => {
            let this_policy = requested_regions.find(x => x.policy === policy.Arn);
            return new Resource({
                is_compliant: (badPolicies.includes(policy.PolicyName)) ? false : true,
                resource_id: policy.PolicyName,
                resource_type: "AWS::IAM::Policy",
                message: (badPolicies.includes(policy.PolicyName)) ? "does not have a RequestedRegion condition assigned." : `has ${this_policy.region} specified as a RequestedRegion.`
            })
        })
    });
};

module.exports = IAMPoliciesHaveRequestedRegion;