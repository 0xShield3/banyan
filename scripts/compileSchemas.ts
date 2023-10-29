import { writeFileSync } from 'fs'
import { join, resolve } from 'path'
import * as TJS from 'typescript-json-schema'

const generate = async () => {
	const settings: TJS.PartialArgs = {
		required: true
	}

	const tsConfigPath = resolve('tsconfig.json')
	const outputPath = resolve('schemas/')

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

		writeFileSync(join(outputPath, `${symbol}.json`), JSON.stringify(schema))
	}
}
generate()
