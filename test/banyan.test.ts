import chai from 'chai'
import { PolicyDecision, policyToJson, validatePolicy, invokePolicyEngine } from '../index'
const { assert } = chai

import AllowRequest from './examples/erc20_limit_allow.json'
import DenyRequest from './examples/erc20_limit_deny.json'

describe('Tests on Banyan', () => {
    it('Allows something', () => {
        const result = invokePolicyEngine(AllowRequest)
        console.log({ result })
        expect(result.decision).toBe(PolicyDecision.ALLOW)
    })

    it('Denies something', () => {
        const result = invokePolicyEngine(DenyRequest)
        console.log({ result })
        expect(result.decision).toBe(PolicyDecision.DENY)
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
        const validationResult = validatePolicy({policy, additional_schema_fragments: [schema]})
        console.log(JSON.stringify(validationResult, null, 2))
        expect(validationResult.valid).toBe(true)

    })
})
