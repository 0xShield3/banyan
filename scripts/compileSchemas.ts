import { appendFileSync } from 'fs'
import { resolve } from 'path'
import * as TJS from 'typescript-json-schema'

const generate = async () => {
	const settings: TJS.PartialArgs = {
		required: true
	}

	const tsConfigPath = resolve('tsconfig.json')
	const outputPath = resolve('schemas/')
	const indexFilePath = resolve('index.ts')


	// const program = TJS.getProgramFromFiles([resolve('services/utils/Interfaces/CommandCenter/IPolicies.ts')])
	const includePaths = [
		resolve('index.ts'),
	]
	const program = TJS.programFromConfig(tsConfigPath, includePaths)

	const generator = TJS.buildGenerator(program, settings)
	if (!generator) throw new Error('No generator')

	const symbols = ['IPolicyEnginePolicyResponse']

	for (const symbol of symbols) {
		// Get symbols for different types from generator.
		const schema = generator.getSchemaForSymbol(symbol)

		appendFileSync(indexFilePath, `\nexport const ${symbol}Schema = ${JSON.stringify(schema, null, 2)}\n`)


	}
}
generate()
