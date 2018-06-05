'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMEnsureSpecifiedGroupsAndRolesExist = {};

IAMEnsureSpecifiedGroupsAndRolesExist.uuid = "1d79b33a-4940-4209-b5ba-9f65b44323b6";
IAMEnsureSpecifiedGroupsAndRolesExist.groupName = "IAM";
IAMEnsureSpecifiedGroupsAndRolesExist.tags = [["NIST", "AC-2", "7(a)"]];
IAMEnsureSpecifiedGroupsAndRolesExist.config_triggers = ["AWS::IAM::Group", "AWS::IAM::Role"];
IAMEnsureSpecifiedGroupsAndRolesExist.paths = {IAMEnsureSpecifiedRolesExist: ["aws_iam_group", "aws_iam_role"]};
IAMEnsureSpecifiedGroupsAndRolesExist.docs = {description: 'The user should specify IAM groups and roles that should exist in each account.', recommended: true};
IAMEnsureSpecifiedGroupsAndRolesExist.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        },
        groups: {
          type: 'array',
          title: 'Groups',
          items: {
              type: 'string'
          }
        },
        roles: {
            type: 'array',
            title: 'Roles',
            items: {
                type: 'string'
            }
        }
    }
};


IAMEnsureSpecifiedGroupsAndRolesExist.livecheck = async function (context) {
    let {config, provider} = context;

    let iam = new provider.IAM();

    let groups = await iam.listGroups().promise();
    let group_names = groups.Groups.map(x => x.GroupName);

    let roles = await iam.listRoles().promise();
    let role_names = roles.Roles.map(x => x.RoleName);

    let groups_and_roles = [...config.groups.map(x => ({type: "group", name: x})), ...config.roles.map(x => ({type: "role", name: x}))];

    let missing_groups = [];
    let missing_roles = [];

    config.groups.map(group => {
       if (!group_names.find(x => x === group)) {
           missing_groups.push(group)
       }
    });

    config.roles.map(role => {
        if (!role_names.find(x => x === role)) {
            missing_roles.push(role)
        }
    });

    return new RuleResult({
        valid: (missing_groups.length > 0 || missing_roles.length > 0) ? "fail" : "success",
        message: "All specified IAM groups and roles should exist in the account.",
        resources: groups_and_roles.map(x => {
            return new Resource({
                is_compliant: (missing_groups.find(group => group === x.name) || missing_roles.find(role => role === x.name)) ? false : true,
                resource_id: (x.type === "group") ? `Group - ${x.name}` : `Role - ${x.name}`,
                resource_type: (x.type === "group") ? "AWS::IAM::Group" : "AWS::IAM::Role",
                message: (missing_groups.find(group => group === x.name) || missing_roles.find(role => role === x.name)) ? "has not been created in this account." : "exists in this account."
            })
        })
    });
};

module.exports = IAMEnsureSpecifiedGroupsAndRolesExist;