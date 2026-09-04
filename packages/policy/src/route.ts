import { PolicyError } from './types.js'

/**
 * A compiled route pattern: an optional method set plus a path glob.
 *
 * Glob semantics, chosen to match what people expect from `.gitignore` and
 * route tables rather than from shell globbing:
 *
 * - `*`  matches within one path segment
 * - `**` matches across segments
 * - `?`  matches a single character within a segment
 * - a trailing `/**` also matches the prefix itself, so `/docs/**` covers
 *   `/docs`, `/docs/`, and `/docs/a/b`
 */
export interface RoutePattern {
  readonly source: string
  readonly methods?: ReadonlySet<string>
  readonly path: RegExp
}

const METHOD_PATTERN = /^[A-Za-z|*]+$/

export function compileRoute(pattern: string, path = 'routes'): RoutePattern {
  const trimmed = pattern.trim()
  if (trimmed === '') throw new PolicyError('route pattern is empty', path)

  const space = trimmed.indexOf(' ')
  let methodPart: string | undefined
  let pathPart = trimmed
  if (space !== -1) {
    methodPart = trimmed.slice(0, space)
    pathPart = trimmed.slice(space + 1).trim()
  }

  if (methodPart !== undefined && !METHOD_PATTERN.test(methodPart)) {
    throw new PolicyError(`invalid method in route pattern: ${methodPart}`, path)
  }
  if (!pathPart.startsWith('/')) {
    throw new PolicyError(`route path must start with "/": ${pathPart}`, path)
  }

  const methods =
    methodPart === undefined || methodPart === '*'
      ? undefined
      : new Set(methodPart.toUpperCase().split('|').filter(Boolean))

  return {
    source: trimmed,
    ...(methods === undefined ? {} : { methods }),
    path: globToRegExp(pathPart),
  }
}

export function matchesRoute(pattern: RoutePattern, method: string, path: string): boolean {
  if (pattern.methods !== undefined && !pattern.methods.has(method.toUpperCase())) return false
  return pattern.path.test(path)
}

function globToRegExp(glob: string): RegExp {
  let out = '^'
  let i = 0
  while (i < glob.length) {
    const c = glob[i] as string
    if (c === '*' && glob[i + 1] === '*') {
      // A trailing "/**" also matches the prefix with no trailing slash, so
      // "/docs/**" covers "/docs" as well as "/docs/a".
      if (out.endsWith('/') && i + 2 === glob.length) {
        out = `${out.slice(0, -1)}(?:/.*)?`
      } else {
        out += '.*'
      }
      i += 2
      continue
    }
    if (c === '*') {
      out += '[^/]*'
    } else if (c === '?') {
      out += '[^/]'
    } else {
      out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    }
    i += 1
  }
  return new RegExp(`${out}$`)
}
