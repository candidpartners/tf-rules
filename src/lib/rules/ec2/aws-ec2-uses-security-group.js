'use strict';
const debug = require('debug')('snitch/aws-ec2-uses-security-group');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2UsesSecurityGroup = {};

EC2UsesSecurityGroup.uuid = "fc877cb6-c786-414a-a06d-50dbde92db74";
EC2UsesSecurityGroup.groupName = "EC2";

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
  let match = false
  let requiredGroups = [];
  let message = null;
  if( context.config ) {
    // debug('Instance: %j', context.instance)
    // debug('Config: %j', context.config)
    if ( _.isArray(context.config)) {
      _.map(context.config, sg => requiredGroups.push(sg))
    } else if ( _.isString(context.config) ) {
      requiredGroups.push(context.config)
    }
    
    _.map(requiredGroups, function(sg) { if ( _.indexOf(context.instance.security_groups, sg) > -1 || _.indexOf(context.instance.vpc_security_group_ids, sg) > -1 ) { match = true } })

    // debug('Required Groups: %j', requiredGroups)

    if( match ) {
      result = {
        valid : 'success'
      };
    } else {
      // debug('Match: %j', match)
      message = context.instance.tags.ApplicationCode + " is not using any of the following security groups: " + requiredGroups.join(', ')
      // debug('Message: %j', message)
      result = {
        valid : 'fail',
        message
      };
      // debug('Result: %j', result)
    }
  }
  return result;
};

module.exports = EC2UsesSecurityGroup;

