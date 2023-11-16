import chai from 'chai'
import { readFileSync, readdirSync } from 'fs'
import { join, resolve } from 'path'
import { PolicyDecision, policyToJson, validatePolicy, invokePolicyEngine, TriggeredPolicyAction, IPolicyEngineInvokePayload } from '../index'

interface ExamplePolicy {
    name: string
    payload: IPolicyEngineInvokePayload
    label: string

}

describe('Example Policy Tests', () => {
    const allowPayloads: ExamplePolicy[] = []
    const denyPayloads: ExamplePolicy[] = []
    
    beforeAll(() => {
	const inputPath = resolve('test/examples')
    const files = readdirSync(inputPath)
    files.forEach((file) => {
        const parsed = file.split('#')
        const name = parsed[0]
        const expectedDecision = parsed[1]
        const label = parsed[2]
        
        const payload = JSON.parse(readFileSync(join(inputPath, file), 'utf-8'))
        
        if (expectedDecision === 'Allow') {
            allowPayloads.push({name, payload, label})
        } else if (expectedDecision === 'Deny') {
            denyPayloads.push({name, payload, label})
        }
    })
    console.log({inputPath, files, allowPayloads, denyPayloads})
    })
    it('Returns valid results for examples', () => {
        allowPayloads.forEach((example) => {
            const result = invokePolicyEngine(example.payload)
            console.log(JSON.stringify(result, null, 2))
            expect(result.decision).toBe(PolicyDecision.ALLOW)
        })
        
        denyPayloads.forEach((example) => {
            const result = invokePolicyEngine(example.payload)
            console.log(JSON.stringify(result, null, 2))
            expect(result.decision).toBe(PolicyDecision.DENY)
        })
    })
})
