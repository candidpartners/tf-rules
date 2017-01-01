'use strict';
const debug     = require('debug')('tfrules/bin/cli');
const fs        = require('fs');
const url       = require('url');
const _         = require('lodash');
const tfRules   = require('../lib');
const getStdin  = require('get-stdin');
const nconf     = require('nconf');
const Plan      = require('tf-parse').Plan;
const colors    = require('colors');
const iniParser = require('ini-parser');
const AWS       = require('aws-sdk');
const yaml      = require('nconf-yaml');
const symbols   = require('../lib/reporters/symbols');

module.exports.main = function *main( testVars ) {
  debug( 'Entry' );
  
  nconf.argv().env().file( { file: 'terraform.tfrules', format: yaml }).defaults( testVars );
  nconf.add( 'provider', { type: 'file', file: 'credentials.tfrules', format: yaml });

  const rules = require( '../lib/rules' );
  module.exports.rules = rules;

  if( ! nconf.get( 'rules' ) ) {
    if( nconf.get( 'config' ) ) {
      nconf.file( 'rules', {
        file: nconf.get( 'config' ),
        format: yaml
      });      
    }
  }
  
  const provider = getProvider( _.defaults( nconf.get('provider'), {} ) );
  
  if( ! nconf.get( 'rules' ) ) {
    console.log( colors.red( 'ERR!' ), ` Could not load configuration from terraform.tfrules file in the ${process.cwd()}. Specify the location of the file using --config` );
    process.exit( 1 );
  }
  
  const config = nconf.get('rules');

  debug( 'Validating config...' );
  
  const errors = tfRules.validateConfig( rules, config );
  
  if( errors.length > 0 ) throw { message : 'Configuration errors', errors };
  
  let inputPlan = '';
  let plan = new Plan();

  if( nconf.get( 'plan' ) ) {
    inputPlan = fs.readFileSync( nconf.get( 'plan' ), 'utf8' );
  } else {
    inputPlan = yield getStdin();
  }
  
  debug( inputPlan );
  
  inputPlan = inputPlan || '';
  
  if( inputPlan.length == 0) {
    console.log( colors.red( 'ERR!' ), " terraform plan input must be specified as a file using --plan or come from stdin" );
    process.exit( 1 );
  }

  debug( 'Parsing plan' );
  let target = plan.parse( inputPlan );
  debug( 'Calling validatePlan' );
  let results = [];
  results = results.concat( yield tfRules.validatePlan( { rules, config, plan : target.add, provider } ) );
  results = results.concat( yield tfRules.validatePlan( { rules, config, plan : target.rep.next, provider } ) );
  results = results.concat( yield tfRules.validatePlan( { rules, config, plan : target.mod.next, provider } ) );

  return results;
};

function getProvider( providerConfig ) {
  const targetConfig = {};
  if( providerConfig.region ) {
    _.defaults( targetConfig, { region : providerConfig.region } );
  }
  if( providerConfig.shared_credentials_file ) {
    const fileContents = fs.readFileSync( providerConfig.shared_credentials_file, 'utf8' );
    const iniConfig = iniParser.parse( fileContents );
    const profile = providerConfig.profile || 'default';
    if( iniConfig[ profile ] ) {
      _.defaults( targetConfig, {
        credentials : {
          accessKeyId     : iniConfig[ profile ].aws_access_key_id,
          secretAccessKey : iniConfig[ profile ].aws_secret_access_key,
          sessionToken    : iniConfig[ profile ].aws_session_token
        }
      });
    } else {
      console.log( colors.red( 'ERR!' ), `provider.shared_credentials_file specified but [${profile}] profile not found` );
      process.exit( 1 );
    }
  }
  
  if( nconf.get( 'HTTPS_PROXY' ) ) {
    const proxy = require('proxy-agent');
    const urlObject = url.parse( nconf.get( 'HTTPS_PROXY' ) );
    urlObject.auth = _.get( urlObject, 'auth', '' ).split(':').map( part => unescape(encodeURIComponent(part)) ).join(':');
    const encodedProxy = url.format( urlObject );
    debug( 'Using proxy of : %s', encodedProxy );
    targetConfig.httpOptions = {
      agent: proxy( encodedProxy )
    };
  }
  AWS.config.update( targetConfig );
  return AWS;
}

module.exports.handleError = function handleError( error ) {
  console.log( error );
  process.exit( 1 );
};

module.exports.handleSuccess = function handleSuccess( value ) {
  let results = _.filter( value, { valid : 'fail' } );
  if( results.length > 0 ) {
    process.exit( 1 );
  } else {
    console.log( colors.green(symbols.ok), `${results.length} tests ran with no errors` );
    process.exit( 0 );
  }
};



