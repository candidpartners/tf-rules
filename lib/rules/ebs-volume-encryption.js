'use strict';

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EBSVolumeEncryption = {};

EBSVolumeEncryption.docs = {
  description: "require EBS volumes have encryption",
  recommended: false
};

EBSVolumeEncryption.liveCheck = true;

EBSVolumeEncryption.schema = {
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

EBSVolumeEncryption.paths = {
  ebsVolume : 'aws_ebs_volume'
};

EBSVolumeEncryption.validate = function( context ) {
  let result = null;
  if( context.config == true ) {
    if( context.instance.encrypted != true ) {
      result = {
        valid : 'fail',
        message : 'EBS Volumes must be configured as true'
      };
    }
  } else if ( context.config == false ) {
    if( context.instance.encrypted == false ) {
      result = {
        valid : 'success'
      };
    } else {
      result = {
        valid : 'fail'
      };
    }
  }
  return result;
};

module.exports = EBSVolumeEncryption;

