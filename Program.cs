using Renci.SshNet;
using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading.Tasks;

class SSHClientWithSocks5Proxy
{
    private SshClient _sshClient;
    private ForwardedPortRemote _remotePortForwarding;
    private TcpListener _socks5Server;

    public SSHClientWithSocks5Proxy(string host, int port, string username, string privateKeyPath)
    {
        // Set up the SSH client using public key authentication (no passphrase)
        var privateKey = new PrivateKeyFile(privateKeyPath);
        var keyFiles = new[] { privateKey };

        _sshClient = new SshClient(host, port, username, keyFiles);
    }

    public void Connect()
    {
        if (!_sshClient.IsConnected)
        {
            Console.WriteLine("Connecting to SSH server...");
            _sshClient.Connect();
            Console.WriteLine("Connected to SSH server.");
        }
    }

    public void StartRemotePortForwarding(string remoteHost, uint remotePort, uint localSocksPort)
    {
        // Forward the SOCKS5 proxy from the client to the remote host on the SSH server
        _remotePortForwarding = new ForwardedPortRemote(remoteHost, remotePort, "127.0.0.1", localSocksPort);

        _sshClient.AddForwardedPort(_remotePortForwarding);
        _remotePortForwarding.Start();

        Console.WriteLine($"Remote port {remoteHost}:{remotePort} is now forwarded to the local SOCKS5 proxy at localhost:{localSocksPort}");
    }

    public void StartSocks5Server(uint localSocksPort)
    {
        _socks5Server = new TcpListener(IPAddress.Parse("127.0.0.1"), (int)localSocksPort);
        _socks5Server.Start();
        Console.WriteLine($"SOCKS5 proxy server started on localhost:{localSocksPort}");

        // Handle incoming SOCKS5 connections in a loop
        Task.Run(async () => {
            while (true)
            {
                TcpClient client = await _socks5Server.AcceptTcpClientAsync();
                HandleSocks5Client(client);
            }
        });
    }

    private async void HandleSocks5Client(TcpClient client)
    {
        using (NetworkStream stream = client.GetStream())
        {
            // Step 1: Handle SOCKS5 handshake
            byte[] request = new byte[3];
            await stream.ReadAsync(request, 0, 3);

            // Validate SOCKS5 version and authentication method (0x05 = SOCKS5, 0x00 = no authentication)
            if (request[0] != 0x05)
            {
                Console.WriteLine("Invalid SOCKS version. Only SOCKS5 is supported.");
                client.Close();
                return;
            }

            // Respond with no authentication required
            byte[] response = { 0x05, 0x00 };
            await stream.WriteAsync(response, 0, response.Length);

            // Step 2: Handle SOCKS5 request (Connect, BIND or UDP ASSOCIATE command)
            byte[] commandRequest = new byte[4];
            await stream.ReadAsync(commandRequest, 0, 4);

            byte command = commandRequest[1]; // The SOCKS5 command: 0x01 = CONNECT, 0x02 = BIND

            if (command == 0x01) // CONNECT command
            {
                await HandleConnectCommand(commandRequest, client, stream);
            }
            else if (command == 0x02) // BIND command
            {
                await HandleBindCommand(commandRequest, client, stream);
            }
            else if (command == 0x03) // UDP ASSOCIATE command
            {
                await HandleUdpAssociateCommand(commandRequest, client, stream);
            }
            else
            {
                Console.WriteLine("Unsupported SOCKS5 command.");
                byte[] failureResponse = { 0x05, 0x07 }; // Command not supported
                await stream.WriteAsync(failureResponse, 0, failureResponse.Length);
                client.Close();
            }
        }
    }

    private async Task HandleConnectCommand(byte[] commandRequest, TcpClient client, NetworkStream stream)
    {
        // Handle the CONNECT command (existing functionality)
        string destinationAddress;
        int destinationPort;

        // Step 3: Parse the destination address and port
        byte addressType = commandRequest[3];
        if (addressType == 0x01) // IPv4
        {
            byte[] addressBytes = new byte[4];
            await stream.ReadAsync(addressBytes, 0, 4);
            destinationAddress = new IPAddress(addressBytes).ToString();
        }
        else if (addressType == 0x03) // Domain name
        {
            byte domainLength = (byte)stream.ReadByte();
            byte[] domainBytes = new byte[domainLength];
            await stream.ReadAsync(domainBytes, 0, domainLength);
            destinationAddress = System.Text.Encoding.ASCII.GetString(domainBytes);
            if (destinationAddress == "xxx.xxx")
            {
                Console.WriteLine("Received exit command. Shutting down...");
                client.Close();
                this.StopServices();
                this.Disconnect();
                System.Environment.Exit(0);
            }
        }
        else
        {
            Console.WriteLine("Unsupported address type.");
            byte[] failureResponse = { 0x05, 0x08 }; // Address type not supported
            await stream.WriteAsync(failureResponse, 0, failureResponse.Length);
            client.Close();
            return;
        }

        // Read destination port (2 bytes)
        byte[] portBytes = new byte[2];
        await stream.ReadAsync(portBytes, 0, 2);
        destinationPort = (portBytes[0] << 8) + portBytes[1];

        Console.WriteLine($"Received SOCKS5 CONNECT request to {destinationAddress}:{destinationPort}");

        // Step 4: Establish connection to the target
        try
        {
            TcpClient targetClient = new TcpClient(destinationAddress, destinationPort);
            Console.WriteLine($"Connected to {destinationAddress}:{destinationPort}");

            // Step 5: Send success response to the SOCKS5 client
            byte[] successResponse = new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80 };
            await stream.WriteAsync(successResponse, 0, successResponse.Length);

            // Step 6: Start forwarding data between the client and the target
            await Task.WhenAll(
                targetClient.GetStream().CopyToAsync(stream),
                stream.CopyToAsync(targetClient.GetStream())
            ).ContinueWith((t) => {
                targetClient.Close();
                client.Close();
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to connect to {destinationAddress}:{destinationPort}. Error: {ex.Message}");
            byte[] failureResponse = { 0x05, 0x01 }; // General failure
            await stream.WriteAsync(failureResponse, 0, failureResponse.Length);
            client.Close();
        }
    }

    private async Task HandleBindCommand(byte[] commandRequest, TcpClient client, NetworkStream stream)
    {
        // Handle the BIND command
        Console.WriteLine("Handling SOCKS5 BIND request...");

        // Step 1: Bind to a local IP and port
        TcpListener listener = new TcpListener(IPAddress.Any, 0); // Bind to any available port
        listener.Start();
        int boundPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        // Step 2: Send the bound address and port back to the client
        byte[] bindResponse = new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (byte)(boundPort >> 8), (byte)(boundPort & 0xFF) };
        await stream.WriteAsync(bindResponse, 0, bindResponse.Length);
        Console.WriteLine($"SOCKS5 BIND: Listening on {((IPEndPoint)listener.LocalEndpoint).Address}:{boundPort}");

        // Step 3: Wait for an incoming connection to the bound port
        TcpClient inboundClient = await listener.AcceptTcpClientAsync();
        Console.WriteLine("SOCKS5 BIND: Incoming connection received.");

        // Step 4: Send the success response to the SOCKS5 client
        await stream.WriteAsync(bindResponse, 0, bindResponse.Length);

        // Step 5: Forward data between the client and the inbound connection
        NetworkStream inboundStream = inboundClient.GetStream();
        await Task.WhenAll(
            inboundStream.CopyToAsync(stream),
            stream.CopyToAsync(inboundStream)
        ).ContinueWith((t) => {
            inboundClient.Close();
            client.Close();
        });
    }

    private async Task HandleUdpAssociateCommand(byte[] commandRequest, TcpClient client, NetworkStream stream)
    {
        Console.WriteLine("Handling SOCKS5 UDP ASSOCIATE request...");

        // Step 1: Parse the client address and port
        byte addressType = commandRequest[3];
        string clientAddress = "";
        int clientPort = 0;

        if (addressType == 0x01) // IPv4
        {
            byte[] addressBytes = new byte[4];
            await stream.ReadAsync(addressBytes, 0, 4);
            clientAddress = new IPAddress(addressBytes).ToString();
        }
        else if (addressType == 0x03) // Domain name
        {
            byte domainLength = (byte)stream.ReadByte();
            byte[] domainBytes = new byte[domainLength];
            await stream.ReadAsync(domainBytes, 0, domainLength);
            clientAddress = System.Text.Encoding.ASCII.GetString(domainBytes);
        }
        else
        {
            Console.WriteLine("Unsupported address type for UDP ASSOCIATE.");
            byte[] failureResponse = { 0x05, 0x08 }; // Address type not supported
            await stream.WriteAsync(failureResponse, 0, failureResponse.Length);
            client.Close();
            return;
        }

        // Read client port (2 bytes)
        byte[] portBytes = new byte[2];
        await stream.ReadAsync(portBytes, 0, 2);
        clientPort = (portBytes[0] << 8) + portBytes[1];

        // Step 2: Set up a UDP socket for forwarding datagrams
        UdpClient udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 0)); // Bind to any available port
        IPEndPoint localEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint;
        Console.WriteLine($"UDP relay listening on {localEndpoint.Address}:{localEndpoint.Port}");

        // Step 3: Send the bound address and port back to the client
        byte[] bindResponse = new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (byte)(localEndpoint.Port >> 8), (byte)(localEndpoint.Port & 0xFF) };
        await stream.WriteAsync(bindResponse, 0, bindResponse.Length);

        // Step 4: Forward UDP packets between client and target
        await Task.Run(async () =>
        {
            while (true)
            {
                var udpResult = await udpClient.ReceiveAsync();
                IPEndPoint clientEndPoint = new IPEndPoint(IPAddress.Parse(clientAddress), clientPort);

                // Here, we would parse the SOCKS5 UDP datagram header and forward the packet.
                // For simplicity, we're forwarding packets as-is.

                // Forward received data to the client
                await udpClient.SendAsync(udpResult.Buffer, udpResult.Buffer.Length, clientEndPoint);
            }
        });

        // Close the connection, since UDP ASSOCIATE doesn't maintain an open TCP connection.
        client.Close();
    }



    public void StopServices()
    {
        if (_remotePortForwarding != null && _remotePortForwarding.IsStarted)
        {
            _remotePortForwarding.Stop();
            Console.WriteLine("Remote port forwarding stopped.");
        }

        _socks5Server?.Stop();
        Console.WriteLine("SOCKS5 proxy server stopped.");
    }
    public void Disconnect()
    {
        if (_sshClient.IsConnected)
        {
            StopServices();
            _sshClient.Disconnect();
            Console.WriteLine("Disconnected from SSH server.");
        }
    }

    static async Task Main(string[] args)
    {
        if (args.Length < 4)
        {
            Console.WriteLine("Usage: SSHClientWithSocks5Proxy <host> <username> <privateKeyPath> <remotePort>");
            return;
        }

        AppDomain.CurrentDomain.AssemblyResolve += (sender, args2) => {

            String resourceName = "AssemblyLoadingAndReflection." +

               new AssemblyName(args2.Name).Name + ".dll";

            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
            {

                Byte[] assemblyData = new Byte[stream.Length];

                stream.Read(assemblyData, 0, assemblyData.Length);

                return Assembly.Load(assemblyData);

            }
        };

        // Parse command-line arguments
        string host = args[0]; // SSH Server IP or hostname
        int sshPort = int.Parse(args[1]); //SSH Port
        string username = args[2]; // SSH Username
        string privateKeyPath = args[3]; // Path to Private Key
        uint remotePort = uint.Parse(args[4]); // Remote port on the SSH server
        uint localSocksPort = 1080; // Local SOCKS5 proxy port

        var sshClient = new SSHClientWithSocks5Proxy(host, sshPort, username, privateKeyPath);

        // Connect to the SSH server
        sshClient.Connect();

        // Start the SOCKS5 proxy server on the client
        sshClient.StartSocks5Server(localSocksPort);

        // Forward the remote port on the server to the local SOCKS5 proxy
        sshClient.StartRemotePortForwarding("127.0.0.1", remotePort, localSocksPort);

        Console.WriteLine("Press any key to stop the SOCKS5 proxy and disconnect...");
        Console.WriteLine("Proxy may also be remotely shut down by sending a connection request to xxx.xxx via the proxy.");
        Console.ReadKey();

        // Stop services and disconnect
        sshClient.Disconnect();
    }
}