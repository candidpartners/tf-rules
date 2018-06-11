'use strict';
const co = require('co')
const debug = require('debug')('snitch/aws-security-group-does-not-allow-outbound');
const _ = require('lodash');
const cidrComparison = require('../../../modules/cidr-comparison');
const portComparison = require('../../../modules/port-comparison');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupDoesNotAllowOutbound = {};

AWSSecurityGroupDoesNotAllowOutbound.uuid = "14065b90-a755-4b78-8ab9-02a19ed7d82f";
AWSSecurityGroupDoesNotAllowOutbound.groupName = "Security Group";
AWSSecurityGroupDoesNotAllowOutbound.tags = [["Candid", "1.0", "13"]];
AWSSecurityGroupDoesNotAllowOutbound.config_triggers = ["AWS::::Account"];
AWSSecurityGroupDoesNotAllowOutbound.paths = {AWSSecurityGroupAllowInbound: 'aws_security_group'};
AWSSecurityGroupDoesNotAllowOutbound.docs = {
    description: 'Security Group does not allow specified outbound traffic.',
    recommended: true
};
AWSSecurityGroupDoesNotAllowOutbound.schema = {
    type: 'object',
    properties: {
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


AWSSecurityGroupDoesNotAllowOutbound.validate = function* (context) {
    // debug( '%O', context );
    let result = null;
    let message = [];
    let groups = {}
    if (context.config) {
        // debug('Config: %j', context.config)
        // debug('Instance: %j', context.instance)
        for (let egress of context.instance.egress) {
            // debug('Egress: %j', egress)
            if (context.config.cidr) {
                groups[context.instance.name] = yield cidrComparison(context.config, egress, false)
            } else if (context.config.port) {
                groups[context.instance.name] = yield portComparison(context.config, egress, false)
            }
        }

        debug('Insecure Groups: %j', groups)
        if (!_.isEmpty(groups[context.instance.name])) {
            _.map(groups[context.instance.name], group => {
                if (group.cidr && !group.ports) {
                    message.push('CIDR Block ' + group.cidr + ' in security group ' + context.instance.name + ' should not be open to outbound traffic to ips: ' + context.config.cidr)
                } else if (group.ports && !group.cidr) {
                    message.push('Security group ' + context.instance.name + ' should not be sending traffic on ports: ' + context.config.port)
                } else if (group.cidr && group.ports) {
                    message.push('CIDR Block ' + group.cidr + ' in security group ' + context.instance.name + ' should not be sending outbound traffic on ports: ' + context.config.port + ' to ips: ' + context.config.cidr)
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

module.exports = AWSSecurityGroupDoesNotAllowOutbound;

