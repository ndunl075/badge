#!/usr/bin/env node
import { run } from './cli.js'
import { consoleIo } from './io.js'

process.exitCode = await run(process.argv.slice(2), consoleIo)
