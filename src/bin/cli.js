'use strict';
const debug = require('debug')('snitch/bin/cli');
const fs = require('fs');
const url = require('url');
const _ = require('lodash');
const tfRules = require('../lib');
const getStdin = require('get-stdin');
const nconf = require('nconf');
const Plan = require('@candidpartners/tf-parse').Plan;
const colors = require('colors');
const iniParser = require('ini-parser');
const AWS = require('aws-sdk');
const yaml = require('nconf-yaml');
const loadYaml = require('js-yaml');
const symbols = require('../lib/reporters/symbols');

const packageJSON = require('../package.json');

//Can comment in to track down where console.logs are coming from

// ['log', 'warn'].forEach(function(method) {
//     var old = console[method];
//     console[method] = function() {
//         var stack = (new Error()).stack.split(/\n/);
//         // Chrome includes a single "Error" line, FF doesn't.
//         if (stack[0].indexOf('Error') === 0) {
//             stack = stack.slice(1);
//         }
//         var args = [].slice.apply(arguments).concat([stack[1].trim()]);
//         return old.apply(console, args);
//     };
// });

function loadConfig() {

    if (!nconf.get('rules')) {
        console.log(colors.red('ERR!'), ` Could not load configuration from terraform.snitch file in the ${process.cwd()}. Specify the location of the file using --config`);
        process.exit(1);
    }

    if (!nconf.get('rules')) {
        if (nconf.get('config')) {
            nconf.file('rules', {
                file: nconf.get('config'),
                format: yaml
            });
        }
    }

    let config = nconf.get('rules');
    const files = fs.readdirSync('.');

    for (let file of files) {
        if (file.endsWith('.snitch') && !file.startsWith('terraform') && !file.startsWith('credentials')) {
            debug('Loading .snitch %s', file);
            const yamlFile = loadYaml.safeLoad(fs.readFileSync(file, 'utf8'));
            if (_.isArray(yamlFile.rules)) {
                config = config.concat(yamlFile.rules);
            }
        }
    }

    module.exports.config = config;

    return config;
}

module.exports.main = function* main(testVars) {
    debug('Entry %O', testVars);

    // CLI only arguments
    let cliArgs = require('nconf').argv();

    // Get Version
    if (cliArgs.get('v') || cliArgs.get('version')) {
        console.log(packageJSON.version);
        process.exit(0)
    }

    // Set up nconf
    nconf.argv().env().file({file: 'snitch.config.yml', format: yaml}).defaults(testVars);

    nconf.add('provider', {type: 'file', file: 'credentials.snitch', format: yaml});

    const provider = yield getProvider(_.defaults(nconf.get('provider'), {}));

    const rules = require('../lib/rules');
    module.exports.rules = rules;

    const config = loadConfig();

    debug('Validating config...');

    const errors = tfRules.validateConfig(rules, config);

    if (errors.length > 0) throw {message: 'Configuration errors', errors};

    let inputPlan = '';
    let plan = new Plan();

    //For livechecks
    if(nconf.get('livecheck')){
        yield tfRules.livecheck({rules, config, provider});
        process.exit(0);
    }
    else{
        // For plans
        if (nconf.get('plan')) {
            inputPlan = fs.readFileSync(nconf.get('plan'), 'utf8');
        } else {
            inputPlan = yield getStdin();
        }

        debug(inputPlan);

        inputPlan = inputPlan || '';

        if (inputPlan.length == 0) {
            console.log(colors.red('ERR!'), " terraform plan input must be specified as a file using --plan or come from stdin");
            process.exit(1);
        }

        debug('Parsing plan');
        let target = plan.parse(inputPlan);
        let results = [];

        if (nconf.get('dryRun') != true) {
            debug('Calling validatePlan');
            results = results.concat(yield tfRules.validatePlan({rules, config, plan: target.add, provider}));
            results = results.concat(yield tfRules.validatePlan({rules, config, plan: target.rep.next, provider}));
            results = results.concat(yield tfRules.validatePlan({rules, config, plan: target.mod.next, provider}));
        }
        return results;
    }
};

function* getProvider(providerConfig) {
    const targetConfig = {};
    if (providerConfig.region) {
        _.defaults(targetConfig, {region: providerConfig.region});
    }

    if (nconf.get('HTTPS_PROXY')) {
        const proxy = require('proxy-agent');
        const urlObject = url.parse(nconf.get('HTTPS_PROXY'));
        urlObject.auth = _.get(urlObject, 'auth', '').split(':').map(part => unescape(encodeURIComponent(part))).join(':');
        const encodedProxy = url.format(urlObject);
        debug('Using proxy of : %s', encodedProxy);
        targetConfig.httpOptions = {
            agent: proxy(encodedProxy)
        };
    }

    if (providerConfig.shared_credentials_file) {
        const fileContents = fs.readFileSync(providerConfig.shared_credentials_file, 'utf8');
        const iniConfig = iniParser.parse(fileContents);
        const profile = providerConfig.profile || 'default';
        if (iniConfig[profile]) {
            _.defaults(targetConfig, {
                credentials: {
                    accessKeyId: iniConfig[profile].aws_access_key_id,
                    secretAccessKey: iniConfig[profile].aws_secret_access_key,
                    sessionToken: iniConfig[profile].aws_session_token
                }
            });
        } else {
            console.log(colors.red('ERR!'), `provider.shared_credentials_file specified but [${profile}] profile not found`);
            process.exit(1);
        }
    } else if (providerConfig.assume_role) {
        debug('assumeRule configured: %O', providerConfig.assume_role);
        const sts = new AWS.STS(_.merge({}, {apiVersion: '2011-06-15'}, targetConfig));
        let params = {
            RoleArn: providerConfig.assume_role.role_arn,
            RoleSessionName: providerConfig.assume_role.session_name,
            DurationSeconds: 3600
        };
        if (_.get(providerConfig.assume_role, 'external_id')) {
            debug('external_id set : %s', providerConfig.assume_role.external_id);
            params.ExternalId = providerConfig.assume_role.external_id;
        }
        debug('assumeRule: %O', params);
        const result = yield sts.assumeRole(params).promise();
        _.defaults(targetConfig, {
            credentials: {
                accessKeyId: result.Credentials.AccessKeyId,
                secretAccessKey: result.Credentials.SecretAccessKey,
                sessionToken: result.Credentials.SessionToken
            }
        });
    }

    AWS.config.update(targetConfig);
    return AWS;
}

module.exports.handleError = function handleError(error) {
    console.log(error);
    process.exit(1);
};

module.exports.handleSuccess = function handleSuccess(value) {
    let results = _.filter(value, {valid: 'fail'});
    if (results.length > 0) {
        process.exit(1);
    } else {
        console.log(colors.green(symbols.ok), `${value.length} tests ran with no errors`);
        process.exit(0);
    }
};



