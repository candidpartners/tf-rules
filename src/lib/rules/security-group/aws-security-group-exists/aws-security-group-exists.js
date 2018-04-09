'use strict';
const debug = require('debug')('snitch/aws-security-group-exists');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupExists = {};

AWSSecurityGroupExists.uuid = "9a17f69d-9b52-4e6c-b612-02ab80ba8eab";
AWSSecurityGroupExists.groupName = "Security Group";
AWSSecurityGroupExists.tags = [["Snitch", "1.0", "14"]];
AWSSecurityGroupExists.config_triggers = ["AWS::Account"];
AWSSecurityGroupExists.paths = {AWSSecurityGroupAllowInbound: 'aws_instance'};
AWSSecurityGroupExists.docs = {
    description: 'Security Groups exist.',
    recommended: true
};

AWSSecurityGroupExists.schema = {type: 'boolean', default: true};


AWSSecurityGroupExists.validate = function* (context) {
    // debug( '%O', context );

    const ec2 = new context.provider.EC2();
    let result = null;
    let sg = null;
    let sgl = [];
    let queryResult = null;
    let missingGroups = [];
    let message = [];
    if (context.config == true) {
        debug('Instance: %j', context.instance.security_groups)
        debug('Instance: %j', context.instance.vpc_security_group_ids)
        if (context.instance.security_groups) {
            _.map(context.instance.security_groups, group => sgl.push(group))
        }

        if (context.instance.vpc_security_group_ids) {
            _.map(context.instance.vpc_security_group_ids, group => sgl.push(group))
        }

        // debug('Security Group List: %j', sgl)

        if (sgl.length > 0) {
            queryResult = yield ec2.describeSecurityGroups({
                Filters: [
                    {
                        'Name': 'group-id',
                        'Values': sgl
                    }
                ]
            }).promise();
        }

        // debug('Query Result: %j', queryResult)

        missingGroups = _.difference(sgl, _.map(_.get(queryResult,'SecurityGroups',[]), 'GroupId'))

        debug('Missing Groups: %j', missingGroups)

        if (missingGroups.length > 0) {
            _.map(missingGroups, group => message.push('Security Group "' + group + '" does not exist'))
            result = {
                valid: 'fail',
                message
            };
        } else {
            result = {
                valid: 'success'
            };
        }
        return result;
    }
};

module.exports = AWSSecurityGroupExists;