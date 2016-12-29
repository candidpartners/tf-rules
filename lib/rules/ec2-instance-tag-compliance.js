'use strict';
const _  = require('lodash');
const debug = require('debug')('tfrules/tag-compliance');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2TagCompliance = {};

EC2TagCompliance.docs = {
  description: "Required tagging must exist",
  recommended: false
};

EC2TagCompliance.schema = {
  type : 'array',
  items : {
    type : 'string'
  }
};

EC2TagCompliance.paths = {
  awsInstance : 'aws_instance'
};

EC2TagCompliance.validate = function( context ) {
  let result = null;
  let tagSpec = null;
  let reqTags = [];
  let message = ''
  debug('Config: %j', context.config)
  for ( let tagSpec of context.config){
    reqTags.push(tagSpec)
    debug('Tag: %j', tagSpec)
  }
  debug('Tag List: %j', reqTags)
  let missingTags = []
  missingTags = _.difference(reqTags, _.keys(context.instance.tags));
  if ( missingTags.length == 0 ) {
    result = { 
      valid : 'success',
    };
  } else {
    message = 'Missing the following tags: ' + missingTags
    result = {
      valid : 'fail',
      message
    };
  }
  return result;
};

module.exports = EC2TagCompliance;

