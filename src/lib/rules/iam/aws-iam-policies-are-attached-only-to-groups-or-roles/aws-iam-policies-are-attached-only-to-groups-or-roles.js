const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMPoliciesAreAttachedOnlyToGroupsOrRoles = {};

IAMPoliciesAreAttachedOnlyToGroupsOrRoles.uuid = "deea587e-7c7a-4319-b570-32abea518f82";
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.groupName = "IAM";
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.tags = ["CIS | 1.1.0 | 1.16"];
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.config_triggers = ["AWS::IAM::User"];
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.paths = {IAMPoliciesAreAttachedOnlyToGroupsOrRoles: "aws_iam_user"};
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.docs = {
    description: 'No IAM Policies are attached directly to a user.',
    recommended: true
};
IAMPoliciesAreAttachedOnlyToGroupsOrRoles.schema = {type: 'boolean', default: true};

IAMPoliciesAreAttachedOnlyToGroupsOrRoles.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let iam = new provider.IAM();

    let users = yield iam.listUsers().promise();
    let userNames = users.Users.map(x => x.UserName);
    let usersWithPolicies = [];

    userNames.map(x => {
        let attached = iam.listAttachedUserPolicies({UserName: x}).promise();
        let userPolicies = iam.listUserPolicies({UserName: x}).promise();
        if (attached.length > 0 || userPolicies.length > 0) {
            usersWithPolicies.push(x)
        }
    });

    if (usersWithPolicies.length > 0) {
        return new RuleResult({
            valid: "fail",
            message: "One or more users have policies directly attached.",
            noncompliant_resources: usersWithPolicies.map(x => new NonCompliantResource({
                resource_id: x,
                resource_type: "AWS::IAM::User",
                message: "has a policy directly attached."
            }))
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

module.exports = IAMPoliciesAreAttachedOnlyToGroupsOrRoles;