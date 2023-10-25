import node_pre_gyp from '@mapbox/node-pre-gyp';
const { find } = node_pre_gyp;
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Native modules are not currently supported with ES module imports.
// https://nodejs.org/api/esm.html#esm_no_native_module_loading
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// __dirname is not defined in ES module scope, so get it manaully.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
    hello,
    authorize,
    // the file will be run in ./dist, so popd.
} = require(find(resolve(join(__dirname, process.env.dev ? '' : '..', './package.json'))));


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
export enum TriggeredPolicyAction {
	BLOCK = 'Block',
	MFA = 'MFA',
	NOTIFY = 'Notify',
	ALLOW = 'Allow'
}

export enum PolicyDecision {
	ALLOW = 'allow',
	DENY = 'deny'
}

export interface IPolicyEnginePolicyResponse {
	action?: TriggeredPolicyAction
	name?: string
	decision: PolicyDecision
	reason: 'true' | 'false'
	message?: string
}

export interface IPolicyEngineInvokeResponse {
	result: {
		[key: string]: IPolicyEnginePolicyResponse
	}
}

export const Banyan = {
  test: 'test'
};

export const invoke = () => {
  console.log('hello');
  return hello();
}

export const isAuthorized = (request: string) => {
  console.log('authorize');
  return authorize(request);
}

export const parsePolicyEngineResponsePayload = (response: any): IPolicyEngineInvokeResponse | null => {
	try {
		const parsedResponse = JSON.parse(response)
    return parsedResponse
		// const validationResult = validatePolicyEngineResponse(parsedResponse)
		// console.log({ validationResult })
		// if (validationResult) return parsedResponse
		// else {
		// 	throw new Error('Failed to validate response')
		// }
	} catch (error) {
		// TODO handle parse error by raising an alert
		console.error('Failed to parse response:', error)
		return null
	}
}

export const invokePolicyEngine = (request: IPolicyEngineInvokePayload): IPolicyEngineInvokeResponse => {
  console.log('invokePolicyEngine');
  const result = isAuthorized(JSON.stringify(request));
  const parsed = parsePolicyEngineResponsePayload(result);
  return parsed
}