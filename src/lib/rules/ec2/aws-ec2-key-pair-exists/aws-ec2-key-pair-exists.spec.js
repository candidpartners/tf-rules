'use strict';
const AWS = require('aws-stub');
const rule = require('./aws-ec2-key-pair-exists');
const _ = require('lodash');
const debug = require('debug')('snitch/aws-ec2-key-pair-exists');

const KeyPairs = [
    {
        'KeyName': 'real-key-name',
        'KeyFingerprint': 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
    },
    {
        'KeyName': 'real-key-name2',
        'KeyFingerprint': 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
    },
    {
        'KeyName': 'wrong-key-name',
        'KeyFingerprint': 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
    },
];

describe('aws-ec2-key-pair-exists', function () {
    it("should return a valid = 'success' when the instance key name is found", async function() {
        const instance = {key_name: 'real-key-name'};
        const provider = AWS('EC2', 'describeKeyPairs', {KeyPairs: [KeyPairs[0]]});
        const context = {config: {enabled: true}, instance, provider};
        const result = await rule.validate(context);
        expect(result.valid).toBe('success');
    });
    it("should return a valid = 'fail' when the instance key name is not found", async function() {
        const instance = {key_name: 'real-key-name'};
        const provider = AWS('EC2', 'describeKeyPairs', {KeyPairs: []});
        const context = {config: {enabled:true}, instance, provider};
        const result = await rule.validate(context);
        expect(result.valid).toBe('fail');
    });
});


describe('aws-ec2-key-pair-exists-livecheck', function () {

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

    it("Should fail if any ec2 instance is found without a key", async function () {
        let provider = getProvider([{KeyName: "MyKey"},{}]);
        let result = await rule.livecheck({provider});
        expect(result.valid).toBe('fail');
        expect(result.message).toBeTruthy();
    });

    it("Should succeed if all ec2 instances are found with a key", async function () {
        let provider = getProvider([{KeyName: "MyKey"},{KeyName: "MyOtherKey"}]);
        let result = await rule.livecheck({provider});
        expect(result.valid).toBe('success');
    });
});

