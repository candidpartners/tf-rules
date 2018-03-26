const Snitch = require('./index');
const {loadConfig} = require('./bin/cli');
const AWS = require('aws-sdk');
AWS.config.update({region: "us-west-2"});

describe("Snitch", () => {
    it("Can be called from JS", async () => {
        let config = Snitch.LoadConfigFromFile(__dirname + "/snitch.config.yml");

        let result = await Snitch.Livecheck({provider: AWS, config, report: false});
        expect(result.length).toBeGreaterThan(0);
    })
});