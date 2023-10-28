import chai from 'chai'
import { PolicyDecision, invoke, invokePolicyEngine } from '../index'
const { assert } = chai

import AllowRequest from './examples/erc20_limit_allow.json'
import DenyRequest from './examples/erc20_limit_deny.json'

describe('Tests on Banyan', () => {
    it('Create something', async () => {
        assert.equal(true, true)
    })

    it('Invoke something', async () => {
        const result = invoke()
        assert.equal(result, 'hello node')
    })

    it('Allows something', async () => {
        const result = invokePolicyEngine(AllowRequest)
        console.log({ result })
        expect(result.decision).toBe(PolicyDecision.ALLOW)
    })

    it('Denies something', async () => {
        const result = invokePolicyEngine(DenyRequest)
        console.log({ result })
        expect(result.decision).toBe(PolicyDecision.DENY)
    })
})
