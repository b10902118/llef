Cast and dereference:

```
>>> lldb.target.GetBasicType(lldb.eBasicTypeInt).GetPointerType()
int *
>>> type(lldb.target.GetBasicType(lldb.eBasicTypeInt).GetPointerType())
<class 'lldb.SBType'>
>>> lldb.frame.register['r0'].Cast(lldb.target.GetBasicType(lldb.eBasicTypeInt).GetPointerType())
(int *) r0 = 0xff9bb2ac
>>> lldb.frame.register['r0']
(unsigned int) r0 = 0xff9bb2ac
>>> r0 = lldb.frame.register['r0'].Cast(lldb.target.GetBasicType(lldb.eBasicTypeInt).GetPointerType())
>>> r0
(int *) r0 = 0xff9bb2ac
>>> r0.Dereference()
(int) *r0 = -6573396
```

# cannot read/write at odd address

lldb➤ mem read -s 1 -c 1 0xc2ff357d
0xc2ff357c: 06

workaround: write 2 bytes from even address

# read string must be null terminated and all printable characters

string=''
e516e810│+0008: 0xc2ff357c → 0x00800a0a

ReadCString not reliable
0xe516e80c│+0004: 0x00293031 ''
<built-in function SBProcess_ReadCStringFromMemory> returned NULL without setting an exception
