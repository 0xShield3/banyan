import chai from 'chai'
import { readFileSync, readdirSync } from 'fs'
import { join, resolve } from 'path'
import { PolicyDecision, policyToJson, validatePolicy, invokePolicyEngine, TriggeredPolicyAction, IPolicyEngineInvokePayload, policyFromJson } from '../index'

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
                allowPayloads.push({ name, payload, label })
            } else if (expectedDecision === 'Deny') {
                denyPayloads.push({ name, payload, label })
            }
        })
        console.log({ inputPath, files, allowPayloads, denyPayloads })
    })
    it('Returns valid results for examples', () => {
        allowPayloads.forEach((example) => {
            // Test str format
            let result = invokePolicyEngine(example.payload)
            expect(result.decision).toBe(PolicyDecision.ALLOW)

            // Test json format
            const jsonPolicy = policyToJson(example.payload.policy)
            const strPolicy = policyFromJson({ policies: jsonPolicy })
            example.payload.policy = strPolicy
            result = invokePolicyEngine(example.payload)
            expect(result.decision).toBe(PolicyDecision.ALLOW)
        })

        denyPayloads.forEach((example) => {
            // Test str format
            let result = invokePolicyEngine(example.payload)
            expect(result.decision).toBe(PolicyDecision.DENY)

            // Test json format
            const jsonPolicy = policyToJson(example.payload.policy)
            const strPolicy = policyFromJson({ policies: jsonPolicy })
            example.payload.policy = strPolicy
            result = invokePolicyEngine(example.payload)
            expect(result.decision).toBe(PolicyDecision.DENY)
        })
    })
})

// describe('Debugging Tests', () => {
//     it('Returns valid results for examples', () => {
//         // const payload = {
//         //     principal: 'Address::"0x2d46abdc57a671adc39bd0340ab8878be32ff6df"',
//         //     action: 'Action::"eoa"',
//         //     resource: 'Address::"0x9c55e8e91fb8e38fb796999f3d22cee91c1274e7"',
//         //     // policy: 'Templates:\n@dependency("verified_addresses:c7bce08d-507a-4768-921e-bdbf23da51d0")\n@message("We need to synthesize the neural USB interface!")\n@name("matrix")\nforbid(\n  principal,\n  action,\n  resource\n) when {\n  (resource has "groups") && ((resource["groups"]).contains(Group::"c7bce08d-507a-4768-921e-bdbf23da51d0"))\n};\n@name("Base Permit")\npermit(\n  principal,\n  action,\n  resource\n) when {\n  true\n};, Template Linked Policies:\n@name("Base Permit")\npermit(\n  principal,\n  action,\n  resource\n) when {\n  true\n};\n@dependency("verified_addresses:c7bce08d-507a-4768-921e-bdbf23da51d0")\n@message("We need to synthesize the neural USB interface!")\n@name("matrix")\nforbid(\n  principal,\n  action,\n  resource\n) when {\n  (resource has "groups") && ((resource["groups"]).contains(Group::"c7bce08d-507a-4768-921e-bdbf23da51d0"))\n};',
//         //     policy: '@name("Base Permit")\npermit(\n  principal,\n  action,\n  resource\n) when {\n  true\n};',
//         //     entities:
//         //         '[{"uid":{"type":"Address","id":"0x2d46abdc57a671adc39bd0340ab8878be32ff6df"},"attrs":{},"parents":[]},{"uid":{"type":"Address","id":"0x9c55e8e91fb8e38fb796999f3d22cee91c1274e7"},"attrs":{},"parents":[]},{"uid":{"type":"Group","id":"c7bce08d-507a-4768-921e-bdbf23da51d0"},"attrs":{},"parents":[]},{"uid":{"type":"Network","id":"0x01"},"attrs":{"blockNumber":18587129},"parents":[]}]',
//         //     context:
//         //         '{"transaction":{"network":{"__entity":{"type":"Network","id":"0x01"}},"data":"0x","value":{"__expr":"u256(\\"100000000000000000\\")"},"gasLimit":{"__expr":"u256(\\"500000\\")"},"threatModuleResults":[]}}',
//         //     schema: undefined
//         // }
//         const payload = {
//             principal: 'Address::"0x44f563da22ac4560391581bbd975ccb1b17db7fc"',
//             action: 'Action::"eoa"',
//             resource: 'Address::"0x7b9ac907351b084398c3d87609b79298427e36fe"',
//             policy: 'Templates:\n@dependency("verified_addresses:6976502a-8561-48fd-9196-e55141d6c1a2")\n@message("The PCI microchip is down, transmit the optical microchip so we can navigate the THX protocol!")\n@name("matrix")\nforbid(\n  principal,\n  action,\n  resource\n) when {\n  (resource has "groups") && ((resource["groups"]).contains(Group::"6976502a-8561-48fd-9196-e55141d6c1a2"))\n};, Template Linked Policies:\n@dependency("verified_addresses:6976502a-8561-48fd-9196-e55141d6c1a2")\n@message("The PCI microchip is down, transmit the optical microchip so we can navigate the THX protocol!")\n@name("matrix")\nforbid(\n  principal,\n  action,\n  resource\n) when {\n  (resource has "groups") && ((resource["groups"]).contains(Group::"6976502a-8561-48fd-9196-e55141d6c1a2"))\n};',
//             entities:
//                 '[{"uid":{"type":"Address","id":"0x44f563da22ac4560391581bbd975ccb1b17db7fc"},"attrs":{},"parents":[]},{"uid":{"type":"Address","id":"0x7b9ac907351b084398c3d87609b79298427e36fe"},"attrs":{},"parents":[]},{"uid":{"type":"Group","id":"6976502a-8561-48fd-9196-e55141d6c1a2"},"attrs":{},"parents":[]},{"uid":{"type":"Network","id":"0x01"},"attrs":{"blockNumber":18587180},"parents":[]}]',
//             context:
//                 '{"transaction":{"network":{"__entity":{"type":"Network","id":"0x01"}},"data":"0x","value":{"__expr":"u256(\\"100000000000000000\\")"},"gasLimit":{"__expr":"u256(\\"500000\\")"},"threatModuleResults":[]}}',
//             schema: undefined
//         }
//         const validationResult = validatePolicy({ policy: payload.policy, additional_schema_fragments: [] })
//         console.log(JSON.stringify(validationResult, null, 2))
//         expect(validationResult.valid).toBe(true)

//         const result = invokePolicyEngine(payload)
//         console.log(JSON.stringify(result, null, 2))
//         expect(result.decision).toBe(PolicyDecision.ALLOW)
//     })
// })
