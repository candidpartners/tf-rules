'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const VPCDefaultSecurityGroupRestrictsAllTraffic = {};

VPCDefaultSecurityGroupRestrictsAllTraffic.uuid = "cd4114a5-a837-4ea4-898f-95a752876265";
VPCDefaultSecurityGroupRestrictsAllTraffic.groupName = "VPC";
VPCDefaultSecurityGroupRestrictsAllTraffic.tags = [["CIS", "1.1.0", "4.4"]];
VPCDefaultSecurityGroupRestrictsAllTraffic.config_triggers = ["AWS::EC2::VPC"];
VPCDefaultSecurityGroupRestrictsAllTraffic.paths = {VPCDefaultSecurityGroupRestrictsAllTraffic: "aws_vpc"};
VPCDefaultSecurityGroupRestrictsAllTraffic.docs = {description: 'The default security group of every VPC should restrict all traffic.', recommended: true};
VPCDefaultSecurityGroupRestrictsAllTraffic.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        }
    }
};


VPCDefaultSecurityGroupRestrictsAllTraffic.livecheck = async function (context) {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let securityGroups = await ec2.describeSecurityGroups().promise();
    let defaultVpcGroups = securityGroups.SecurityGroups.filter(x => x.GroupName === "default");
    let unrestrictedDefaults = defaultVpcGroups.filter(x => x.IpPermissions.length > 0 || x.IpPermissionsEgress.length > 0);

    return new RuleResult({
        valid: (unrestrictedDefaults.length > 0) ? "fail" : "success",
        message: "The default security group of every VPC should restrict all traffic.",
        resources: defaultVpcGroups.map(group => {

            let inbound = group.IpPermissions.length > 0;
            let outbound = group.IpPermissionsEgress.length > 0;

            return new Resource({
                is_compliant: (inbound || outbound) ? false : true,
                resource_id: `${group.VpcId} ${group.GroupName}`,
                resource_type: "AWS::EC2::VPC",
                message: (inbound && outbound) ? "allows both inbound and outbound traffic." : inbound ? "allows inbound traffic." : outbound ? "allows outbound traffic." : "restricts all traffic."
            })
        })
    });
};

module.exports = VPCDefaultSecurityGroupRestrictsAllTraffic;