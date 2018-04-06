'use strict';
const debug = require('debug')('snitch/lib');
const _ = require('lodash');
const co = require('co');
const Ajv = require('ajv');
const colors = require('colors');
const jp = require('jmespath');

const symbols = require('./reporters/symbols');

const ajv = new Ajv();

function getKey(ob) {
    if (!_.isObject(ob)) {
        throw {severity: 'error', message: 'An individual rule configuration must be an object'};
    }
    const keys = _.keys(ob);
    if (keys.length != 1) {
        throw {
            severity: 'error',
            message: 'An individual rule configuration must have a single key that is the name of the rule'
        };
    }
    return keys[0];
}

function validateConfig(rules, config) {
    let errors = [];
    try {
        if (!_.isArray(config)) {
            errors.push({severity: 'error', message: 'The rules configuration must be an array.'});
        } else {
            errors = _.reduce(config, (accum, item) => {
                let ruleId = getKey(item);
                let rule = rules[ruleId];
                let ruleConfig = item[ruleId];
                if (rule == undefined) {
                    accum.push({severity: 'warning', message: `${ruleId} rule not available in this version`});
                } else if (!ajv.validate(rule.schema || {}, ruleConfig)) {
                    accum.push({
                        severity: 'error',
                        message: `${ruleId} configuration invalid`,
                        details: JSON.stringify(ajv.errors, null, 2)
                    });
                }
                return accum;
            }, errors);
        }
    } catch (err) {
        errors.push(err);
    }
    return errors;
}

function report(result, instanceName, rule, ruleId) {
    console.log(colors.white(`\n${ruleId}`));
    if (result) {
        if (result.valid == 'success') {
            console.log(colors.green(symbols.ok), colors.green(' OK'), colors.gray(rule.docs.description), instanceName && colors.gray(':'), instanceName);
        } else if (result.valid == 'fail') {
            //Print out message
            if (_.isArray(result.message)) {
                for (let error of result.message) {
                    console.log(colors.red(symbols.err), colors.red('ERR'), colors.gray(error || rule.docs.description), instanceName && colors.gray(':'), instanceName);
                }
            } else {
                console.log(colors.red(symbols.err), colors.red('ERR'), colors.gray(result.message || rule.docs.description), instanceName && colors.gray(':'), instanceName);
            }
            //Print out non-compliant resources
            if (result.noncompliant_resources) {
                result.noncompliant_resources.forEach(x => {
                    console.log('\t', colors.red(x.resource_id), colors.gray(x.message))
                })
            }
        }
    }
}

function* validatePlan(params) {
    const plan = params.plan;
    const provider = params.provider;
    debug('allConfig: %j', params.config);
    let results = [];
    if (_.isObject(plan) && !_.isArray(plan) && !_.isEmpty(plan)) {
        for (let ruleInstance of params.config) {
            debug('ruleInstance: %j', ruleInstance);
            let ruleId = getKey(ruleInstance);
            let rule = params.rules[ruleId];
            let config = ruleInstance[ruleId];
            let paths = rule.paths;
            let searchResults = _.keys(paths).map(path => ({
                rule: ruleId,
                path: {
                    name: path,
                    query: paths[path]
                },
                search: jp.search(plan, paths[path])
            }));

            for (let searchResult of searchResults) {
                if (_.isObject(searchResult.search) && !_.isArray(searchResult.search)) {
                    for (let instanceName of _.keys(searchResult.search)) {
                        let instance = searchResult.search[instanceName];
                        let result = yield rule.validate({config, instance, plan, jp, provider, _});
                        results.push(result);
                        report(result, instanceName, rule, ruleId);
                    }
                }
            }
        }
    }
    return results;
}

let livecheck = co.wrap(function* (params) {
    const provider = params.provider;
    let config_triggers = params.config_triggers || [];

    debug('allConfig: %j', params.config);

    let promises = [];
    for (let ruleInstance of params.config) {
        debug('ruleInstance: %j', ruleInstance);
        let ruleId = getKey(ruleInstance);
        let rule = params.rules[ruleId];
        let config = ruleInstance[ruleId];

        //If config_triggers, skip over if not in the triggers
        if (config_triggers.length) {
            let rule_triggers = rule.config_triggers || [];
            let isTrigger = _.intersection(config_triggers, rule_triggers).length > 0;
            if (!isTrigger)
                continue;
        }

        // If the rule has a livecheck, call it and add it to the promise array
        if (_.isFunction(rule.livecheck)) {
            let promise = rule.livecheck({config, provider}).then(result => ({
                rule,
                ruleId,
                result
            }));
            promises.push(promise)
        }
    }
    // Report back
    let results = yield Promise.all(promises);
    results.forEach(({rule, ruleId, result}) => {
        if (params.report)
            report(result, "", rule, ruleId);
    });

    return results.map(x => {
        if(x.result)
            return x.result
        else
            throw x
    });
});

module.exports = {
    validateConfig,
    validatePlan,
    livecheck
};

