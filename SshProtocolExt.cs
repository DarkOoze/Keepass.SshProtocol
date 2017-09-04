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
	using KeePass.Plugins;
	using KeePassLib.Serialization;

	public sealed class SshProtocolExt : Plugin
	{
		private static readonly string[] protocols = { "SCP", "SFTP" };
		private static bool propertiesRegistered;
		private IPluginHost PluginHost;

		public override string UpdateUrl => "https://gist.githubusercontent.com/DarkOoze/c15877ea271a136e0644e38b0c017751/raw/2134a78854b33316eb379c1ee3224fea5e84252e/KeePassVersionVersionInformationFile";

		public override bool Initialize(IPluginHost host)
		{
			if (this.PluginHost != null)
			{
				this.Terminate();
			}

			if (host == null)
			{
				return false;
			}

			this.PluginHost = host;

			RegisterPlugin();

			return true;
		}

		public override void Terminate()
		{
			if (this.PluginHost != null)
			{
				this.PluginHost = null;
			}
		}

		private static void RegisterPlugin()
		{
			if (propertiesRegistered)
			{
				return;
			}

			propertiesRegistered = true;

			var creator = new SshRequestCreator();

			foreach (var protocol in protocols)
			{
				System.Net.WebRequest.RegisterPrefix(protocol, creator);
			}

			IocPropertyInfoPool.Add(new IocPropertyInfo(PropertyKeys.PrivateKey,
				typeof(string), "SSH private key path", protocols));
			IocPropertyInfoPool.Add(new IocPropertyInfo(PropertyKeys.HostKey,
				typeof(string), "Fingerprint of expected SSH host key", protocols));
		}
	}
}