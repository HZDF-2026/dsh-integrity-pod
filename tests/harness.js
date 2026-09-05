export function mockExec(over = {}) {
  return {
    callId: 'call-1',
    name: 'test-tool',
    arguments: {},
    token: 'tok-1',
    signal: new AbortController().signal,
    agent: null,
    ...over,
  }
}

// Poll an async condition until truthy. The guardrail audit log appends are
// fire-and-forget promises (the plugin must never block the tool loop), so
// tests wait on observable file state instead of fixed setImmediate ticks.
export async function waitFor(predicate, { timeoutMs = 5000, intervalMs = 5 } = {}) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await predicate()
    if (value) return value
    if (Date.now() >= deadline) return value
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
}

export function makeCtx() {
  const registeredTools = []
  const listeners = new Map()
  const ctx = {
    tools: {
      register: (definition) => registeredTools.push(definition),
    },
    on: (event, handler) => {
      if (!listeners.has(event)) listeners.set(event, [])
      listeners.get(event).push(handler)
    },
    effect: (setup) => {
      const dispose = setup()
      return typeof dispose === 'function' ? dispose : () => {}
    },
  }
  return {
    ctx,
    registeredTools,
    tool(name) {
      const tool = registeredTools.find((entry) => entry.name === name)
      if (!tool) throw new Error(`tool not registered: ${name}`)
      return tool
    },
    async call(name, args, execOver = {}) {
      const tool = this.tool(name)
      return JSON.parse(await tool.execute(args, mockExec(execOver)))
    },
    async preExecute(exec, nextResult = { kind: 'allow' }) {
      const handlers = listeners.get('tools/pre-execute') ?? []
      if (handlers.length === 0) throw new Error('no tools/pre-execute listener registered')
      const next = async () => nextResult
      return handlers[handlers.length - 1](exec, next)
    },
    emit(event, ...args) {
      for (const handler of listeners.get(event) ?? []) handler(...args)
    },
  }
}
