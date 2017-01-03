'use strict';
const debug = require('debug')('tfrules/aws-ec2-instance-uses-security-group');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2UsesSecurityGroup = {};

EC2UsesSecurityGroup.docs = {
  description: 'EC2 Instance Uses Specified Security Groups',
  recommended: true
};

EC2UsesSecurityGroup.schema = {
  anyOf : [
    { type : 'string' },
    { 
      type : 'array',
      items : { type : 'string' }
    }
  ]
};

EC2UsesSecurityGroup.paths = {
  rdsInstance : 'aws_instance'
};

EC2UsesSecurityGroup.validate = function *( context ) {
  // debug( '%O', context );

  let result = null;
  let requiredGroups = [];
  let includedGroups = [];
  let message = [];
  if( context.config ) {
    // debug('Instance: %j', context.instance)
    if ( _.isArray(context.config)) {
      _.map(context.config, sg => requiredGroups.push(sg))
    } else if ( _.isString(context.config) ) {
      requiredGroups.push(context.config)
    }

    _.map(context.instance.security_groups, sg => includedGroups.push(sg))
    _.map(context.instance.vpc_security_group_ids, sg => includedGroups.push(sg))

    let missingGroups = _.difference(requiredGroups, includedGroups)

    debug('Missing Groups: %j', missingGroups)
    debug('Required Groups: %j', requiredGroups)
    debug('Included Groups: %j', includedGroups)

    if( missingGroups == 0 ) {
      result = {
        valid : 'success'
      };
    } else {
      _.map( missingGroups, group => message.push(context.instance.tags.ApplicationCode + " is not using the '" + group + "' security group"))
      result = {
        valid : 'fail',
        message
      };
    }
  }
  return result;
};

module.exports = EC2UsesSecurityGroup;

