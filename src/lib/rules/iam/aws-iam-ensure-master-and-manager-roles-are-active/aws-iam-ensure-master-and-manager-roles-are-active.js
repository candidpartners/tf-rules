// @flow
const {Resource,RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMMasterAndManagerRolesAreActive = {};

IAMMasterAndManagerRolesAreActive.uuid = "69fe01f9-b2d5-47a4-b33f-5b86a98b5722";
IAMMasterAndManagerRolesAreActive.groupName = "IAM";
IAMMasterAndManagerRolesAreActive.tags = [["CIS", "1.1.0", "1.18"]];
IAMMasterAndManagerRolesAreActive.config_triggers = ["AWS::IAM::Role"];
IAMMasterAndManagerRolesAreActive.paths = {IAMMasterAndManagerRolesAreActive: "aws_iam_role"};
IAMMasterAndManagerRolesAreActive.docs = {description: 'Both Master and Manager IAM roles are active.', recommended: true};
IAMMasterAndManagerRolesAreActive.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


IAMMasterAndManagerRolesAreActive.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */{
    let {config, provider} = context;
    let iam = new provider.IAM();

    let roles = await iam.listRoles().promise();
    let masterRole = roles.Roles.find(x => x.RoleName === "IAM_Master");
    let managerRole = roles.Roles.find(x => x.RoleName === "IAM_Manager");

    let inactive = [];
    if (!masterRole) {
        inactive.push({RoleName: "IAM_Master"});
    }
    if (!managerRole) {
        inactive.push({RoleName: "IAM_Manager"});
    }

    return new RuleResult({
        valid: (!masterRole || !managerRole) ? "fail" : "success",
        message: "IAM must have Master and Manager Roles",
        resources: [
            {
                is_compliant: masterRole ? true : false,
                resource_id: "IAM_Master",
                resource_type: "AWS::IAM::Role",
                message: masterRole ? "exists and is functioning." : "does not exist."
            },
            {
                is_compliant: managerRole ? true : false,
                resource_id: "IAM_Manager",
                resource_type: "AWS::IAM::Role",
                message: managerRole ? "exists and is functioning." : "does not exist."
            }
        ]
    });
};

module.exports = IAMMasterAndManagerRolesAreActive;