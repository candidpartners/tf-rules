'use strict';
const _ = require('lodash');
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const VPCRoutingTablesForVPCPeeringAreLeastAccess = {};

VPCRoutingTablesForVPCPeeringAreLeastAccess.uuid = "d522ae6a-d185-44b7-9bab-98a6d2e24958";
VPCRoutingTablesForVPCPeeringAreLeastAccess.groupName = "VPC";
VPCRoutingTablesForVPCPeeringAreLeastAccess.tags = [["CIS", "1.1.0", "4.5"]];
VPCRoutingTablesForVPCPeeringAreLeastAccess.config_triggers = ["AWS::EC2::VPC"];
VPCRoutingTablesForVPCPeeringAreLeastAccess.paths = {VPCRoutingTablesForVPCPeeringAreLeastAccess: "aws_vpc"};
VPCRoutingTablesForVPCPeeringAreLeastAccess.docs = {description: 'Routing tables for VPC peering should be "least access"', recommended: false};
VPCRoutingTablesForVPCPeeringAreLeastAccess.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        }
    }
};

// I think this rule works, but I haven't been able to set up a resource to confirm a successful livecheck


VPCRoutingTablesForVPCPeeringAreLeastAccess.livecheck = async function (context) {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let peeringConnections = await ec2.describeVpcPeeringConnections().promise();
    let routeTables = await ec2.describeRouteTables().promise();

    let peeringConnectionIds = peeringConnections.VpcPeeringConnections.map(x => x.VpcPeeringConnectionId);

    let gatewayIds = routeTables.RouteTables.map(x => {
        x.Routes.map(y => y.GatewayId)
    });

    let connectionsWithGatewayIds = _.intersection(peeringConnectionIds, gatewayIds);
    let connectionsWithoutGatewayIds = peeringConnectionIds.filter(x => !connectionsWithGatewayIds.includes(x));

    return new RuleResult({
        valid: (connectionsWithoutGatewayIds.length > 0) ? "fail" : "success",
        message: "Routing tables for VPC peering should be 'least access'",
        resources: peeringConnections.VpcPeeringConnections.map(connection => {
            return new Resource({
                is_compliant: (connectionsWithoutGatewayIds.includes(connection.VpcPeeringConnectionId)) ? false : true,
                resource_id: connection.VpcPeeringConnectionId,
                resource_type: "AWS::EC2::VPC",
                message: (connectionsWithoutGatewayIds.includes(connection.VpcPeeringConnectionId)) ? "does not have an associated route in any route tables." : "is established in a route table."
            })
        })
    });
};

module.exports = VPCRoutingTablesForVPCPeeringAreLeastAccess;