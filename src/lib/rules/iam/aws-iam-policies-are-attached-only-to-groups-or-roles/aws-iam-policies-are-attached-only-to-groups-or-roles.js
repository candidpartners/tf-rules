// @flow
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMPoliciesAreAttachedOnlyToGroupsOrRoles = {};

IAMPoliciesAreAttachedOnlyToGroupsOrRoles.uuid = "deea587e-7c7a-4319-b570-32abea518f82";
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.groupName = "IAM";
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.tags = [["CIS", "1.1.0", "1.16"]];
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.config_triggers = ["AWS::IAM::User"];
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.paths = {IAMPoliciesAreAttachedOnlyToGroupsOrRoles: "aws_iam_user"};
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.docs = {
    description: 'No IAM Policies are attached directly to a user.',
    recommended: true
};
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.schema = {type: 'boolean', default: true};

IAMPoliciesAreAttachedOnlyToGroupsOrRoles.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let iam = new provider.IAM();

    let users = await iam.listUsers().promise();
    let userNames = users.Users.map(x => x.UserName);
    let usersWithPolicies = [];

    userNames.map(x => {
        let attached = iam.listAttachedUserPolicies({UserName: x}).promise();
        let userPolicies = iam.listUserPolicies({UserName: x}).promise();
        if (attached.length > 0 || userPolicies.length > 0) {
            usersWithPolicies.push(x)
        }
    });

    let isInvalid = usersWithPolicies.length > 0;
    return new RuleResult({
        valid: isInvalid ? "fail" : "success",
        message: "Users should not have policies directly attached",
        resources: usersWithPolicies.map(x => new Resource({
            is_compliant: false,
            resource_id: x,
            resource_type: "AWS::IAM::User",
            message: "has a policy directly attached."
        }))
    })
};

module.exports = IAMPoliciesAreAttachedOnlyToGroupsOrRoles;