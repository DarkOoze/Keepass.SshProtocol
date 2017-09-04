// MIT License
//
// Copyright(c) 2017
// Anders Hörnfeldt
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


namespace SshProtocol
{
	using KeePassLib.Serialization;
	using Renci.SshNet;
	using Renci.SshNet.Common;
	using System;
	using System.Collections.Generic;
	using System.IO;
	using System.Net;

	public class SshRequestCreator : IWebRequestCreate
	{
		private readonly static int DefaultPort = 22;
		private static Dictionary<string, SftpClient> clientCache = new Dictionary<string, SftpClient>(StringComparer.CurrentCultureIgnoreCase);

		public WebRequest Create(Uri uri)
		{
			return new SshWebRequest(uri);
		}

		private static SftpClient CreateClient(SshWebRequest webRequest)
		{
			SftpClient client;
			var cred = (NetworkCredential)webRequest.Credentials;
			var port = webRequest.RequestUri.Port > 0 ? webRequest.RequestUri.Port : DefaultPort;
			var privateKey = webRequest.IOConnectionProperties.Get(PropertyKeys.PrivateKey);

			if (privateKey != null && File.Exists(privateKey))
			{
				client = new SftpClient(webRequest.RequestUri.Host, port, cred.UserName, new PrivateKeyFile(privateKey));
			}
			else
			{
				client = new SftpClient(webRequest.RequestUri.Host, port, cred.UserName, cred.Password);
			}

			if (webRequest.Timeout > 0)
			{
				client.OperationTimeout = TimeSpan.FromMilliseconds(webRequest.Timeout);
			}

			client.Connect();

			return client;
		}

		private static SftpClient GetOrCreateClient(SshWebRequest request)
		{
			string key = request.RequestUri.Host + request.RequestUri.Port;

			if (!clientCache.ContainsKey(key) || !(clientCache[key]?.IsConnected ?? false))
			{
				clientCache[key] = CreateClient(request);
			}

			return clientCache[key];
		}

		private class SshWebRequest : WebRequest, IHasIocProperties
		{
			private SftpClient client;

			public SshWebRequest(Uri uri)
			{
				this.RequestUri = uri;
			}

			public override long ContentLength { get; set; }

			public override string ContentType { get; set; }

			public override ICredentials Credentials { get; set; }

			public override WebHeaderCollection Headers { get; set; } = new WebHeaderCollection();

			public IocProperties IOConnectionProperties { get; set; }

			public override string Method { get; set; }

			public override IWebProxy Proxy { get; set; }

			public override Uri RequestUri { get; }

			public override int Timeout { get; set; }

			public override void Abort()
			{
				this.client.Disconnect();
				this.client = null;
			}

			public override Stream GetRequestStream()
			{
				if (this.client == null || !this.client.IsConnected)
				{
					this.client = SshRequestCreator.GetOrCreateClient(this);
				}

				return this.client.OpenWrite(this.RequestUri.AbsolutePath.TrimStart('/'));
			}

			public override WebResponse GetResponse()
			{
				WebResponse response = null;

				if (this.client == null || !this.client.IsConnected)
				{
					this.client = SshRequestCreator.GetOrCreateClient(this);
				}

				switch (this.Method)
				{
					case IOConnection.WrmDeleteFile:
						response = SshWebResponse.GetDeleteResponse(this.client, this.RequestUri.AbsolutePath);
						break;

					case IOConnection.WrmMoveFile:
						var moveTo = this.Headers[IOConnection.WrhMoveFileTo];
						var authority = this.RequestUri.GetLeftPart(UriPartial.Authority);

						if (moveTo?.StartsWith(authority) == true)
						{
							response = SshWebResponse.GetMoveResponse(this.client, this.RequestUri.AbsolutePath.TrimStart('/'), moveTo.Substring(authority.Length).TrimStart('/'));
						}

						break;

					case null:
						response = SshWebResponse.GetDownloadResponse(this.client, this.RequestUri.AbsolutePath);
						break;
				}

				return response ?? new SshWebResponse();
			}

			private void ClientOnHostKeyReceived(object sender, HostKeyEventArgs hostKeyEventArgs)
			{
				var expectedHostKey = this.IOConnectionProperties.Get(PropertyKeys.HostKey);
				var fingerprint = BitConverter.ToString(hostKeyEventArgs.FingerPrint);

				if (expectedHostKey != null && expectedHostKey.Equals(fingerprint, StringComparison.OrdinalIgnoreCase))
				{
				}
			}
		}

		private class SshWebResponse : WebResponse
		{
			private Stream stream;

			public override long ContentLength => this.stream.Length;

			public override string ContentType
			{
				get { return "application/octet-stream"; }
				set { throw new InvalidOperationException(); }
			}

			public static SshWebResponse GetDeleteResponse(SftpClient client, string path)
			{
				var response = new SshWebResponse();

				if (client.Exists(path))
				{
					client.DeleteFile(path);
				}

				path = path.TrimStart('/');

				if (client.Exists(path))
				{
					client.DeleteFile(path);
				}

				return response;
			}

			public static SshWebResponse GetDownloadResponse(SftpClient client, string path)
			{
				var response = new SshWebResponse();

				if (client.Exists(path))
				{
					response.stream = client.OpenRead(path);
					return response;
				}

				path = path.TrimStart('/');

				if (client.Exists(path))
				{
					response.stream = client.OpenRead(path);
					return response;
				}

				return response;
			}

			public static SshWebResponse GetMoveResponse(SftpClient client, string pathFrom, string pathTo)
			{
				var response = new SshWebResponse();

				if (client.Exists(pathFrom))
				{
					client.RenameFile(pathFrom, pathTo);
				}

				return response;
			}

			public override void Close()
			{
				this.stream?.Close();
				this.stream?.Dispose();
			}

			public override Stream GetResponseStream()
			{
				if (this.stream != null)
				{
					this.stream.Position = 0;
				}

				return this.stream;
			}
		}
	}
}