// @flow
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMSupportRoleIsAttached = {};

IAMSupportRoleIsAttached.uuid = "5302e8ca-c6af-4f11-9389-431b029d15a9";
IAMSupportRoleIsAttached.groupName = "IAM";
IAMSupportRoleIsAttached.tags = [["CIS", "1.1.0", "1.22"]];
IAMSupportRoleIsAttached.config_triggers = ["AWS::IAM::Role"];
IAMSupportRoleIsAttached.paths = {IAMSupportRoleHasBeenCreated: "aws_iam_role"};
IAMSupportRoleIsAttached.docs = {
    description: 'The AWSSupportAccess IAM role is attached to one or more roles, groups, or users.',
    recommended: true
};
IAMSupportRoleIsAttached.schema = {type: 'boolean', default: false};


IAMSupportRoleIsAttached.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let iam = new provider.IAM();

    let policy = await iam.getPolicy({PolicyArn: "arn:aws:iam::aws:policy/AWSSupportAccess"}).promise();

    let isInvalid = (policy.AttachmentCount === 0);
    return new RuleResult({
        valid: isInvalid ? "fail" : "success",
        message: "The AWSSupportAccess policy is not attached to any roles, groups, or users.",
        resources: [new Resource({
            is_compliant: isInvalid ? false : true,
            resource_id: "AWSSupportAccess",
            resource_type: "AWS::IAM::Policy",
            message: "is not attached to any roles, groups, or users."
        })]
    })
};

module.exports = IAMSupportRoleIsAttached;