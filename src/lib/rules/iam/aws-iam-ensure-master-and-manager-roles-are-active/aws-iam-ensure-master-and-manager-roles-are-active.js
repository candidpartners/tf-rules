const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

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
IAMMasterAndManagerRolesAreActive.schema = {type: 'boolean'};


IAMMasterAndManagerRolesAreActive.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let iam = new provider.IAM();

    let roles = yield iam.listRoles().promise();
    let masterRole = roles.Roles.find(x => x.RoleName === "IAM_Master");
    let managerRole = roles.Roles.find(x => x.RoleName === "IAM_Manager");

    let inactive = [];
    if (!masterRole) {
        inactive.push({RoleName: "IAM_Master"});
    }
    if (!managerRole) {
        inactive.push({RoleName: "IAM_Manager"});
    }

    if (inactive.length > 0) {
        return new RuleResult({
            valid: "fail",
            message: "One or both of the IAM Master and IAM Manager roles are not active.",
            noncompliant_resources: inactive.map(x => new NonCompliantResource({
                resource_id: x.RoleName,
                resource_type: "AWS::IAM::Role",
                message: "is not active"
            }))
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

module.exports = IAMMasterAndManagerRolesAreActive;