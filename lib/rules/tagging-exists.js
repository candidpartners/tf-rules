'use strict';
const _  = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const taggingExists = {};

taggingExists.docs = {
  description: "Required tagging must exist",
  recommended: false
};

const requiredTags = [
  'Name',
  'ApplicationId',
  'ApplicationCode',
  'Environment',
  'CostCenter'
]

taggingExists.liveCheck = false;

taggingExists.schema = {
  anyOf: [
    { type : 'boolean' },
    {
      type: 'object',
      properties : {
        exclude : {
          type : 'array',
          items : {
            type : 'string'
          }
        },
        include : {
          type : 'array',
          items : {
            type : 'string'
          }
        }
      }
    }
  ]
};

taggingExists.paths = {
  awsInstance : 'aws_instance'
};

taggingExists.validate = function( context ) {
  let result = null;
  if (context.config == true) {
    let missingTags = _.difference(requiredTags, _.keys(context.instance.tags));
    if ( missingTags.length == 0 ) {
      result = { 
        valid : 'success',
      };
    } else {
      let message = 'Missing the following tags: ' + missingTags
      result = {
        valid : 'fail',
        message
      };
    }
  } else {
    result = { 
      valid : 'success',
    };
  }
  return result;
};

module.exports = taggingExists;

