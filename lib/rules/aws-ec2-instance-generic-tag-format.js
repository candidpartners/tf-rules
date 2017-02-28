'use strict';
const _  = require('lodash');
const debug = require('debug')('tfrules/generic-tag-format');
const XRegExp = require('XRegExp');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2GenericTagFormat = {};

EC2GenericTagFormat.docs = {
  description: "All tag values must match generic AWS format",
  recommended: true
};

EC2GenericTagFormat.schema = {
  type : 'boolean'
};

EC2GenericTagFormat.paths = {
  awsInstance : 'aws_instance'
};

EC2GenericTagFormat.validate = function( context ) {
  let result = null;
  let matchErrors = [];
  let message = ''

  debug('Config: %j', context.config)

  if(context.config != true) {
    debug('Generic tag format check is disabled and tags will not be validated');
    return {
      'valid' : 'success'
    };
  }

  let re = new XRegExp('^([\\pL\\pZ\\pN_.:\/=+\-@]*)$');
  for (let tagName of _.keys(context.instance.tags)) {
    try {
      if (!re.test(context.instance.tags[tagName])) {
        matchErrors.push(`Tag ${tagName} (${context.instance.tags[tagName]}) does not match required AWS format`);
      }
    } catch(e) {
      matchErrors.push(e)
    }

    debug('Tag: %j', tagName)
  }

  if (matchErrors.length == 0) {
    result = {
      'valid' : 'success'
    }
  } else {
    result = {
      valid : 'fail',
      message : matchErrors
    }
  }

  return result;
};

module.exports = EC2GenericTagFormat;
