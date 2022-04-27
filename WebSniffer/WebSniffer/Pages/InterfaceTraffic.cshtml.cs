using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using PacketDotNet;
using SharpPcap;

namespace WebSniffer.Pages
{
    public class InterfaceTrafficModel : PageModel
    {
        public ICaptureDevice device { get; set; }
        public string[] devicePorp { get; set; }
        public List<string> packets { get; set; }
        private bool capture { get; set; }
        [Parameter]
        public string ip { get; set; }

        public void OnGet()
        {
            capture = false;            
            device = CaptureDeviceList.Instance.FirstOrDefault(x => parseDevice(x)[1] == ip);
            if (device == null)
                Redirect("/");
            devicePorp = parseDevice(device);
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(OnPacketArrival);            
        }

        public void OnPostCapture()
        {
            if (capture == false)
            {
                capture = true;

                device.Open();
                device.Filter = "ip and tcp";
                device.StartCapture();
            }
            else
            {
                capture = false;

                device.StopCapture();
                device.Close();
            }
        }

        public void OnPacketArrival(object sender, PacketCapture e)
        {
            var packet = Packet.ParsePacket(e.Device.LinkType, e.Data.ToArray());
            string tablePacket = packet.ToString().Replace("][", "]\n\n[");
            if (packet != null && packet.PayloadPacket != null && packet.PayloadPacket.PayloadPacket != null &&
                packet.PayloadPacket.GetType() == typeof(IPv4Packet) &&
                packet.PayloadPacket.PayloadPacket.GetType() == typeof(TcpPacket))
            {
                var ipv4 = (IPv4Packet)packet.PayloadPacket;
                var tcp = (TcpPacket)ipv4.PayloadPacket;

                tablePacket += ("\nFrom: ");
                try { tablePacket += Dns.GetHostEntry(ipv4.SourceAddress).HostName; }
                catch { tablePacket += ipv4.SourceAddress; }
                tablePacket += $" :{tcp.SourcePort}";

                tablePacket += "To: ";
                try { tablePacket += Dns.GetHostEntry(ipv4.DestinationAddress).HostName; }
                catch { tablePacket += ipv4.DestinationAddress; }
                tablePacket += $" :{tcp.DestinationPort}";
            }
            packets.Add(tablePacket);
        }

        private string[] parseDevice(ICaptureDevice dev)
        {
            char[] separators = new char[] { '\n', ':' };
            string name = "";
            string ipAddress = "";

            string[] splitStr = dev.ToString().Split(separators);
            for (int i = 0; i < splitStr.Length; i++)
            {
                if (splitStr[i].Equals("FriendlyName"))
                {
                    name = splitStr[i + 1].Trim();
                }
                else if (splitStr[i].Equals("Addr"))
                {
                    if (splitStr[i + 1].Contains('.'))
                    {
                        ipAddress = splitStr[i + 1].Trim();
                    }
                }
            }
            if (name.Length == 0)
            {
                if (splitStr.Length > 7)
                {
                    name = splitStr[4].Trim();
                }
            }
            if (name.Length == 0)
            {
                name = dev.ToString();
            }
            return new string[] { name, ipAddress };
        }
    }
}
