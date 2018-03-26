'use strict';
const AWS = require('aws-stub');
const rule = require('./aws-ec2-instance-tag-exists');
const co = require('co');
const _ = require('lodash');
const debug = require('debug')('snitch/aws-ec2-instance-tag-exists');

const InstanceTags = [
    {
        tagKey: "MyTag1",
        tagValue: "MyTagValue1"
    },
    {
        tagKey: "MyTag2",
        tagValue: "MyTagValue2"
    },
    {
        tagKey: "MyTag3",
        tagValue: "MyTagValue3"
    }
];

describe('aws-ec2-instance-tag-exists', function () {
    it("should return a valid = 'success' when the instance tag name is found", co.wrap(function* () {
        const instance = {tag_key: 'real-tag-key'};
        const provider = AWS('EC2', 'describeInstanceTags', {InstanceTags: [InstanceTags[0]]});
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("should return a valid = 'fail' when the instance tag name is not found", co.wrap(function* () {
        const instance = {tag_key: 'real-tag-key'};
        const provider = AWS('EC2', 'describeInstanceTags', {InstanceTags: []});
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));
});


describe('aws-ec2-instance-tag-exists-livecheck', function () {

    function getProvider(instances){
        return {
            EC2: class EC2 {
                constructor(Instances){
                    this._instances = Instances;
                }

                describeInstances(){
                    return {
                        promise: () => {
                            return Promise.resolve({
                                Reservations:[
                                    {
                                        Instances: instances
                                    }
                                ]
                            })
                        }
                    }
                }
            }
        };
    }

    it("Should fail if any ec2 instance is found without a tag", async function () {
        let provider = getProvider([{TagKey: "MyTag"},{}]);
        let result = await rule.livecheck({provider});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("One or more of your EC2 instances do not have an Instance Tag.");
    });

    it("Should succeed if all ec2 instances are found with a tag", async function () {
        let provider = getProvider([{TagKey: "MyTag"},{TagKey: "MyOtherTag"}]);
        let result = await rule.livecheck({provider});
        expect(result.valid).toBe('success');
    })
});
