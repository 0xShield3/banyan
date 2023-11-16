import chai from 'chai'
import { PolicyDecision, policyToJson, validatePolicy, invokePolicyEngine, policyFromJson } from '../index'
const { assert } = chai

import AllowRequest from './examples/erc20_limit_allow.json'
import DenyRequest from './examples/erc20_limit_deny.json'

describe('Tests on Banyan', () => {
    it('Allows something', () => {
        const result = invokePolicyEngine(AllowRequest)
        console.log(JSON.stringify(result, null, 2))
        expect(result.decision).toBe(PolicyDecision.ALLOW)
    })

    it('Allows something using json policy', () => {
        const policyJson = policyToJson(AllowRequest.policy)
        const policyString = policyFromJson({ policies: policyJson })
        AllowRequest.policy = policyString
        const result = invokePolicyEngine(AllowRequest)
        console.log(JSON.stringify(result, null, 2))
        expect(result.decision).toBe(PolicyDecision.ALLOW)
    })

    it('Denies something', () => {
        const result = invokePolicyEngine(DenyRequest)
        console.log(JSON.stringify(result, null, 2))
        expect(result.decision).toBe(PolicyDecision.DENY)
    })

    it('Denies something with JSON policy ', () => {
        const policyJson = policyToJson(DenyRequest.policy)
        const policyString = policyFromJson({ policies: policyJson })
        DenyRequest.policy = policyString
        const result = invokePolicyEngine(DenyRequest)
        console.log(JSON.stringify(result, null, 2))
        expect(result.decision).toBe(PolicyDecision.DENY)
    })

    it.only('Returns string representation of a policy', () => {
        const policy = AllowRequest.policy
        const policyJson = policyToJson(policy)
        console.log(JSON.stringify(policyJson, null, 2))
        const policyString = policyFromJson({ policies: policyJson })
        console.log(policyString)
        expect(policyJson).toBeDefined()
        expect(policyString).toBeDefined()
    })

    it('Returns JSON representation of a policy', () => {
        const policy = AllowRequest.policy
        const policyJson = policyToJson(policy)
        console.log(JSON.stringify(policyJson, null, 2))
        expect(policyJson).toBeDefined()
    })

    it('Returns validation results', () => {
        const policy = AllowRequest.policy
        const schema = AllowRequest.schema
        const validationResult = validatePolicy({ policy, additional_schema_fragments: [schema] })
        console.log(JSON.stringify(validationResult, null, 2))
        expect(validationResult.valid).toBe(true)
    })

    it('Returns validation results with json policy', () => {
        const policy = AllowRequest.policy
        const policyJson = policyToJson(policy)
        const policyString = policyFromJson({ policies: policyJson })

        const schema = AllowRequest.schema
        const validationResult = validatePolicy({ policy: policyString, additional_schema_fragments: [schema] })
        console.log(JSON.stringify(validationResult, null, 2))
        expect(validationResult.valid).toBe(true)
    })
})
