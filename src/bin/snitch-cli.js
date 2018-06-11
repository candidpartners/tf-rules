#!/usr/bin/env node
const AWS = require('aws-sdk');
const program = require('commander');
const packageJson = require('../package.json');
const fs = require('fs');
const yaml = require('js-yaml');
const cp = require('child_process');

const Plan = require('@candidpartners/tf-parse').Plan;

const rules = require('../lib/rules');
const snitch = require('../lib');
const DotFile = require('./dot-file-parser');


// Livecheck
program
    .command("livecheck")
    .option("-c, --config <config_file>")
    .action((context) => {
        let config = GetConfigFile(context.config);
        AWS.config.update({ region: config.provider.region });
        snitch.livecheck({
            rules,
            config: config.rules,
            provider: AWS,
            report: true
        })
            .then(OnSuccessfulRun)
            .catch(OnError)
    })


// Terraform
program
    .command("terraform")
    .option('-o, --output', "Output the plan and graph files")
    .option('-p, --plan <plan_file>', 'Use a given terraform plan file')
    .option('-g, --graph <graph_file>', 'Use a given terraform graph file')
    .action((context) => {
        let config = GetConfigFile(context.config);
        AWS.config.update({ region: config.provider.region });

        // Plan Output
        let planOutput;
        if (context.plan) {
            console.log(`Reading plan file from ${context.plan}`)
            planOutput = fs.readFileSync(context.plan).toString();
        } else {
            console.log("Running terraform plan");
            planOutput = cp.execSync("terraform plan -no-color").toString();
            if (context.output) {
                fs.writeFileSync('./plan_output.txt', planOutput)
            }
        }

        // Graph Output
        let graphOutput;
        if (context.graph) {
            console.log(`Reading plan file from ${context.graph}`);
            graphOutput = fs.readFileSync(context.graph).toString();
        } else {
            console.log("Running terraform graph")
            graphOutput = cp.execSync("terraform graph").toString();
            if (program.output) {
                fs.writeFileSync('./graph_output.txt', graphOutput)
            }
        }

        // Run Terraform Check
        terraformCheck({ config, planOutput, graphOutput })
            .then(OnSuccessfulRun)
            .catch(OnError)
    })

// Set up CLI
program.parse(process.argv);


/*
 * END CLI
 */

async function terraformCheck({ config, planOutput, graphOutput }) {
    // Get Plan
    let plan = new Plan();
    let target = plan.parse(planOutput);
    let results = [];

    // Get Graph Object
    let graph = new DotFile(graphOutput);

    console.log("Validating terraform plan")
    results = results.concat(await snitch.validatePlan({ rules, config: config.rules, plan: target.add, provider: AWS, graph }));
    results = results.concat(await snitch.validatePlan({ rules, config: config.rules, plan: target.rep.next, provider: AWS, graph }));
    results = results.concat(await snitch.validatePlan({ rules, config: config.rules, plan: target.mod.next, provider: AWS, graph }));
    return results;
}

function GetConfigFile(config_path = "snitch.config.yml") {
    return yaml.safeLoad(fs.readFileSync(config_path, 'utf8'));
}

function OnSuccessfulRun(result) {
    if (result.every(x => x.valid === 'success')) {
        console.log('All resources are compliant')
        process.exit(0);
    } else {
        console.log('Some resources are not compliant')
        process.exit(1);
    }
}

function OnError(error) {
    throw error
}