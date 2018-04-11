const rule = require('./aws-ec2-instance-tag-exists');
const AWS = require('aws-stub');


describe("aws-ec2-instance-tag-exists", () => {
    it("Can perform a livecheck", async () => {
        let provider = AWS("EC2", "describeInstances",
            {
                Reservations: [
                    {
                        Instances: [
                            {
                                // Other instance data just omitted
                                Tags: [{Key: "MyTag"}]
                            },
                            {
                                Tags: [{Key: "MyTag"},{Key: "OtherTag"}]
                            }
                        ]
                    }
                ]
            }
        );
        let result = await rule.livecheck({config: ["MyTag"], provider});
        expect(result.valid).toBe("success");

        let failResult = await rule.livecheck({config:["OtherTag"], provider});
        expect(failResult.valid).toBe('fail');
        expect(failResult.message).toBe("EC2 Instances must have specified tags");
    });

    it("Can perform a tfcheck", async () => {
        let instance = {
            tags: {}
        };

        let config = ["MyTag"];
        let result = rule.validate({instance, config});
        expect(result.valid).toBe('fail');
        expect(result.message).toEqual(["MyTag tag is missing"]);

        let instance2 = {
            tags: {"MyTag": "MyValue"}
        };

        let result2 = rule.validate({instance: instance2, config});
        expect(result2.valid).toBe('success');
    })
});