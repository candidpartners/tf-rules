'use strict';
const debug = require('debug')('snitch/lib');
const _ = require('lodash');
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
                    accum.push({severity: 'error', message: `${ruleId} configuration invalid`, details: ajv.errors});
                }
                return accum;
            }, errors);
        }
    } catch (err) {
        errors.push(err);
    }
    return errors;
}

function report(result, instanceName, rule) {
    if (result) {
        if (result.valid == 'success') {
            console.log(colors.green(symbols.ok), colors.green(' OK'), colors.gray(rule.docs.description), instanceName && colors.gray(':'), instanceName);
        } else if (result.valid == 'fail') {
            if (_.isArray(result.message)) {
                for (let error of result.message) {
                    console.log(colors.red(symbols.err), colors.red('ERR'), colors.gray(error || rule.docs.description), instanceName && colors.gray(':'), instanceName);
                }
            } else {
                console.log(colors.red(symbols.err), colors.red('ERR'), colors.gray(result.message || rule.docs.description), instanceName && colors.gray(':'), instanceName);
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
                        report(result, instanceName, rule);
                    }
                }
            }
        }
    }
    return results;
}

function* livecheck(params) {
    const provider = params.provider;
    debug('allConfig: %j', params.config);
    let results = [];
    for (let ruleInstance of params.config) {
        debug('ruleInstance: %j', ruleInstance);
        let ruleId = getKey(ruleInstance);
        let rule = params.rules[ruleId];
        let config = ruleInstance[ruleId];

        if(_.isFunction(rule.livecheck)){
            let result = yield rule.livecheck({config, provider});
            results.push(result);
            report(result, "", rule);
        }

        // let paths = rule.paths;
        // let searchResults = _.keys(paths).map(path => ({
        //     rule: ruleId,
        //     path: {
        //         name: path,
        //         query: paths[path]
        //     },
        //     search: jp.search(plan, paths[path])
        // }));
        // for (let searchResult of searchResults) {
        //     if (_.isObject(searchResult.search) && !_.isArray(searchResult.search)) {
        //         for (let instanceName of _.keys(searchResult.search)) {
        //             let instance = searchResult.search[instanceName];
        //
        //         }
        //     }
        // }
    }
    return results;
}


module.exports = {
    validateConfig,
    validatePlan,
    livecheck
};

