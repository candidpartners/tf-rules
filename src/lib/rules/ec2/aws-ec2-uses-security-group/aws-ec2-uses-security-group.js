'use strict';
const debug = require('debug')('snitch/aws-ec2-uses-security-group');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2UsesSecurityGroup = {};

EC2UsesSecurityGroup.uuid = "fc877cb6-c786-414a-a06d-50dbde92db74";
EC2UsesSecurityGroup.groupName = "EC2";
EC2UsesSecurityGroup.tags = [["Candid", "1.0", "7"]];
EC2UsesSecurityGroup.config_triggers = ["AWS::EC2::Instance"];
EC2UsesSecurityGroup.paths = {EC2UsesSecurityGroup: 'aws_instance'};
EC2UsesSecurityGroup.docs = {
    description: 'All EC2 instances use specified security groups.',
    recommended: true
};
EC2UsesSecurityGroup.schema = {
    type: 'object',
    properties: {
        enabled: {type: "boolean", title: "Enabled"},
        security_groups: {
            title: "Security group names",
            type: "array",
            items: {type: 'string'}
        }
    }
};


EC2UsesSecurityGroup.validate = async function (context) {
    // debug( '%O', context );

    let result = null;
    let match = false;
    let requiredGroups = context.config.security_groups || [];
    let message = null;
    if (context.config) {
        // debug('Instance: %j', context.instance)
        // debug('Config: %j', context.config)
        _.map(requiredGroups, function (sg) {
            if (_.indexOf(context.instance.security_groups, sg) > -1 || _.indexOf(context.instance.vpc_security_group_ids, sg) > -1) {
                match = true
            }
        })

        // debug('Required Groups: %j', requiredGroups)

        if (match) {
            result = {
                valid: 'success'
            };
        } else {
            // debug('Match: %j', match)
            message = context.instance.tags.ApplicationCode + " is not using any of the following security groups: " + requiredGroups.join(', ')
            // debug('Message: %j', message)
            result = {
                valid: 'fail',
                message
            };
            // debug('Result: %j', result)
        }
    }
    return result;
};

module.exports = EC2UsesSecurityGroup;

