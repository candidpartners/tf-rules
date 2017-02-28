'use strict';
const _  = require('lodash');
const debug = require('debug')('tfrules/tag-exists');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2TagExists = {};

EC2TagExists.docs = {
  description: "Required tagging must exist",
  recommended: false
};

EC2TagExists.schema = {
  type : 'array',
  items : {
    type : 'string'
  }
};

EC2TagExists.paths = {
  awsInstance : 'aws_instance'
};

EC2TagExists.validate = function( context ) {
  let result = null;
  let tagSpec = null;
  let reqTags = [];
  let message = []
  debug('Config: %j', context.config)
  for ( let tagSpec of context.config){
    reqTags.push(tagSpec)
    debug('Tag: %j', tagSpec)
  }
  debug('Tag List: %j', reqTags)
  let missingTags = []

  // if the plan is a modification to an existing resource, don't check
  // for tag existance - those will not be present in the modification plan
  if(context.planType != 'modify') {
    missingTags = _.difference(reqTags, _.keys(context.instance.tags));
  }

  debug('Missing Tags: %j', missingTags)
  for (let item of missingTags){
    message.push(item + ' tag is missing')
  }
  if ( missingTags.length == 0 ) {
    result = {
      valid : 'success',
    };
  } else {
    result = {
      valid : 'fail',
      message
    };
  }
  return result;
};

module.exports = EC2TagExists;

