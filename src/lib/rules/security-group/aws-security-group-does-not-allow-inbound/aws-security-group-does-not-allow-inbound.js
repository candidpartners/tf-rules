'use strict';
const co = require('co');
const debug = require('debug')('snitch/aws-security-group-does-not-allow-inbound');
const _ = require('lodash');
const cidrComparison = require('../../../modules/cidr-comparison');
const portComparison = require('../../../modules/port-comparison');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupDoesNotAllowInbound = {};

AWSSecurityGroupDoesNotAllowInbound.uuid = "67477475-5d35-4444-bcb4-0c9053aa357e";
AWSSecurityGroupDoesNotAllowInbound.groupName = "Security Group";
AWSSecurityGroupDoesNotAllowInbound.tags = [["CIS", "1.1.0", "4.1"], ["CIS", "1.1.0", "4.2"]];
AWSSecurityGroupDoesNotAllowInbound.config_triggers = ["AWS::EC2::SecurityGroup"];
AWSSecurityGroupDoesNotAllowInbound.paths = {AWSSecurityGroupAllowInbound: 'aws_security_group'};
AWSSecurityGroupDoesNotAllowInbound.docs = {
    description: 'Security Group does not allow specified inbound traffic.',
    recommended: true
};
AWSSecurityGroupDoesNotAllowInbound.schema = {
    type: 'object',
    properties: {
        enabled: {type: "boolean", title: "Enabled", default: true},
        cidr: {
            type: 'string',
            title: 'CIDR',
            pattern: "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"
        },
        ports: {
            type: 'array',
            title: 'Port numbers',
            items: {
                type: 'string',
                pattern: '^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])[\-]?([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?$'
            }
        }
    }
};

AWSSecurityGroupDoesNotAllowInbound.livecheck = async function (context) {
    let {config, provider} = context;
    let ec2 = new provider.EC2();

    let securityGroups = await ec2.describeSecurityGroups().promise();
    let badGroups = [];

    securityGroups.SecurityGroups.map(group => {
        group.IpPermissions.map(permission => {
            let ranges = _.flatten(permission.IpRanges.map(x => Object.values(x)));

            if (ranges.includes("0.0.0.0/0")) {
                if (permission.ToPort === 22 || permission.ToPort === 3389) {
                    badGroups.push(group.GroupName);
                }
            }
        })
    });

    return new RuleResult({
        valid: (badGroups.length > 0) ? "fail" : "success",
        message: "No security groups should allow ingress from 0.0.0.0/0 to either port 22 or 3389.",
        resources: securityGroups.SecurityGroups.map(group => {

            let port = group.IpPermissions.map(x => x.ToPort).filter(x => x === 22 || x === 3389);

            return new Resource({
                is_compliant: badGroups.includes(group.GroupName) ? false : true,
                resource_id: group.GroupName,
                resource_type: "AWS::EC2::SecurityGroup",
                message: badGroups.includes(group.GroupName) ? `allows ingress from 0.0.0.0/0 to port ${port}.` : `does not allow ingress from 0.0.0.0/0 to either port 22 or 3389.`
            })
        })
    })
};

AWSSecurityGroupDoesNotAllowInbound.validate = function* (context) {
    // debug( '%O', context );
    let result = null;
    let message = [];
    let groups = {};
    if (context.config) {
        // debug('Config: %j', context.config)
        // debug('Instance: %j', context.instance)
        for (let ingress of context.instance.ingress) {
            // debug('Ingress: %j', ingress)
            // debug('Send Groups: %j', groups)
            if (context.config.cidr) {
                groups[context.instance.name] = yield cidrComparison(context.config, ingress, false)
            } else if (context.config.port) {
                groups[context.instance.name] = yield portComparison(context.config, ingress, false)
            }
        }

        debug('Insecure Groups: %j', groups)
        if (!_.isEmpty(groups[context.instance.name])) {
            debug('Insecure Groups: %j', groups)
            _.map(groups[context.instance.name], group => {
                if (group.cidr && !group.ports) {
                    message.push('CIDR Block ' + group.cidr + ' in security group ' + context.instance.name + ' should not be open to inbound traffic from ips: ' + context.config.cidr)
                } else if (group.ports && !group.cidr) {
                    message.push('Security group ' + context.instance.name + ' should not be taking traffic on ports: ' + context.config.port)
                } else if (group.cidr && group.ports) {
                    message.push('CIDR Block ' + group.cidr + ' in security group ' + context.instance.name + ' should not be taking inbound traffic on ports: ' + context.config.port + ' from ips: ' + context.config.cidr)
                }
            })
            result = {
                valid: 'fail',
                message
            }
        } else {
            result = {
                valid: 'success'
            };
        }
    }
    ;
    debug('Result: %j', result)
    return result;
};

module.exports = AWSSecurityGroupDoesNotAllowInbound;

