const co = require('co');
const Papa = require('papaparse');
const {Resource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMSupportRoleIsAttached = {};

IAMSupportRoleIsAttached.uuid = "5302e8ca-c6af-4f11-9389-431b029d15a9";
IAMSupportRoleIsAttached.groupName = "IAM";
IAMSupportRoleIsAttached.tags = [["CIS", "1.1.0", "1.22"]];
IAMSupportRoleIsAttached.config_triggers = ["AWS::IAM::Role"];
IAMSupportRoleIsAttached.paths = {IAMSupportRoleHasBeenCreated: "aws_iam_role"};
IAMSupportRoleIsAttached.docs = {description: 'The AWSSupportAccess IAM role is attached to one or more roles, groups, or users.', recommended: true};
IAMSupportRoleIsAttached.schema = {type: 'boolean', default: false};


IAMSupportRoleIsAttached.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let iam = new provider.IAM();

    let policy = yield iam.getPolicy({PolicyArn: "arn:aws:iam::aws:policy/AWSSupportAccess"}).promise();

    if (policy.AttachmentCount === 0) {
        return new RuleResult({
            valid: "fail",
            message: "The AWSSupportAccess policy is not attached to any roles, groups, or users.",
            noncompliant_resources: new Resource({
                resource_id: "AWSSupportAccess",
                resource_type: "AWS::IAM::Policy",
                message: "is not attached to any roles, groups, or users."
            })
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

module.exports = IAMSupportRoleIsAttached;