import node_pre_gyp from '@mapbox/node-pre-gyp'
const { find } = node_pre_gyp
import { resolve, join, dirname } from 'path'
import { fileURLToPath } from 'url'
import Ajv from 'ajv'

import PolicyEngineResponse from './schemas/IPolicyEnginePolicyResponse.json'

// Native modules are not currently supported with ES module imports.
// https://nodejs.org/api/esm.html#esm_no_native_module_loading
import { createRequire } from 'module'
const require = createRequire(import.meta.url)

// __dirname is not defined in ES module scope, so get it manaully.
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const {
    hello,
    authorize,
    policy_to_json,
    validate_policy,
    // the file will be run in ./dist, so popd.
} = require(find(resolve(join(__dirname, process.env.dev ? '' : '..', './package.json'))))

export interface IBanyan {}

export interface IPolicyEngineInvokePayload {
    principal: string
    action: string
    resource: string
    policy: string
    entities: string
    context: string
    schema: string | undefined
}

export interface IValidatePolicyPayload {
    policy: string
    additional_schema_fragments: string[]
}

export enum TriggeredPolicyAction {
    MFA = 'MFA',
    NOTIFY = 'Notify',
}

export enum PolicyDecision {
    ALLOW = 'Allow',
    DENY = 'Deny',
}

export interface IPolicyStatementResult {
    name?: string
    message?: string
    action?: TriggeredPolicyAction
    invoked: boolean
}

export interface IPolicyEnginePolicyResponse {
    reasons: IPolicyStatementResult[]
    decision: PolicyDecision
    errors: string[]
}

export interface IPolicyJSON {
    effect: 'forbid' | 'permit'
    principal: any
    action: any
    resource: any
    conditions: any[]
    annotations: {
        [key: string]: string
    }
}

export type PolicyToJSONResponse = IPolicyJSON[]

export const invoke = () => {
    console.log('hello')
    return hello()
}

export const isAuthorized = (request: string) => {
    console.log('authorize')
    return authorize(request)
}

export function validatePolicyEngineResponse(maybePolicyEngineResponse: any) {
    const ajv = new Ajv()
    const validate = ajv.compile(PolicyEngineResponse)
    return validate(maybePolicyEngineResponse)
}

export const parsePolicyEngineResponsePayload = (response: any): IPolicyEnginePolicyResponse | null => {
    try {
        const parsedResponse = JSON.parse(response)
        const validationResult = validatePolicyEngineResponse(parsedResponse)
        console.log({ validationResult })
        if (validationResult) return parsedResponse
        else {
            throw new Error('Failed to validate response')
        }
    } catch (error) {
        // TODO handle parse error by raising an alert
        console.error('Failed to parse response:', error)
        return null
    }
}

export const invokePolicyEngine = (request: IPolicyEngineInvokePayload): IPolicyEnginePolicyResponse => {
    console.log('invokePolicyEngine')
    const result = isAuthorized(JSON.stringify(request))
    const parsed = parsePolicyEngineResponsePayload(result)
    return parsed
}

export const policyToJson = (policy: string): PolicyToJSONResponse => {
    console.log('policyToJson')
    const result = policy_to_json(policy)
    const parsedResponse: PolicyToJSONResponse = JSON.parse(result) // TODO validate
    return parsedResponse
}

export const validatePolicy = (request: IValidatePolicyPayload): any => {
    console.log('validatePolicy')
    const result = validate_policy(JSON.stringify(request))
    const parsedResponse = JSON.parse(result) // TODO validate
    return parsedResponse
}
