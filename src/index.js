const fs = require('fs');
const YAML = require('yamljs');
const Snitch = require('./lib/index');
const SnitchCLI = require('./bin/cli');
const Rules = require('./lib/rules/index');

function Livecheck({provider,config, rules = Rules, config_triggers = []}){
    const errors = Snitch.validateConfig(rules, config);
    if (errors.length > 0) throw {message: 'Configuration errors', errors};

    return Snitch.livecheck({provider,config,rules, config_triggers})
};

function LoadConfigFromFile(path){
    let content = fs.readFileSync(path).toString();
    return YAML.parse(content).rules;
}

module.exports = {
    Livecheck,
    LoadConfigFromFile,
    SnitchCLI,
    Rules
};
