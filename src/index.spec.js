const Snitch = require('./index');
const {loadConfig} = require('./bin/cli');
const AWS = require('aws-sdk');
AWS.config.update({region: "us-west-2"});


jest.setTimeout(15000);

describe("Snitch", () => {
    it("Can be called from JS", async () => {
        let config = Snitch.LoadConfigFromFile(__dirname + "/snitch.config.yml");

        let result = await Snitch.Livecheck({provider: AWS, config, report: false});
        console.log(result);
        expect(result.length).toBeGreaterThan(0);
    });

    it("Can be given a list of AWS Config Triggers", async () => {
        let config = Snitch.LoadConfigFromFile(__dirname + "/snitch.config.yml");

        // Expect some to trigger off of "AWS::EC2::Instance"
        let result = await Snitch.Livecheck({
            provider: AWS,
            config,
            report: false,
            config_triggers: ["AWS::EC2::Instance"]
        });
        expect(result.length).toBeGreaterThan(0);

        // Expect none to trigger off of "AWS::EC2::FOO"
        let result2 = await Snitch.Livecheck({
            provider: AWS,
            config,
            report: false,
            config_triggers: ["AWS::EC2::FOO"]
        });

        expect(result2.length).toBe(0);
    })
},10000);