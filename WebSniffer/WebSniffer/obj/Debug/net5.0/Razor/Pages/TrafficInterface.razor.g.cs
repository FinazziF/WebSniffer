#pragma checksum "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "b88173f270f3898cd853f64ae97d9080dbf13ebe"
// <auto-generated/>
#pragma warning disable 1591
namespace WebSniffer.Pages
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
#nullable restore
#line 2 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using SharpPcap;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using PacketDotNet;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using System.Net;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using Microsoft.AspNetCore.Components;

#line default
#line hidden
#nullable disable
#nullable restore
#line 6 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using Microsoft.AspNetCore.Components.Web;

#line default
#line hidden
#nullable disable
    [Microsoft.AspNetCore.Components.RouteAttribute("/TrafficInterface/{ip}")]
    public partial class TrafficInterface : Microsoft.AspNetCore.Components.ComponentBase
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
            __builder.OpenElement(0, "h2");
            __builder.AddContent(1, 
#nullable restore
#line 8 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
     devicePorp[0]

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(2, "\r\n");
            __builder.OpenElement(3, "h3");
            __builder.AddContent(4, 
#nullable restore
#line 9 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
     devicePorp[1]

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(5, "\r\n<br>\r\n\r\n");
            __builder.OpenElement(6, "button");
            __builder.AddAttribute(7, "class", "btn btn-primary");
            __builder.AddAttribute(8, "type", "submit");
            __builder.AddAttribute(9, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create<Microsoft.AspNetCore.Components.Web.MouseEventArgs>(this, 
#nullable restore
#line 12 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                                        CaptureStart

#line default
#line hidden
#nullable disable
            ));
            __builder.AddContent(10, "Start Capture");
            __builder.CloseElement();
            __builder.AddMarkupContent(11, "\r\n<br>\r\n<br>\r\n");
            __builder.OpenElement(12, "button");
            __builder.AddAttribute(13, "class", "btn btn-primary");
            __builder.AddAttribute(14, "type", "submit");
            __builder.AddAttribute(15, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create<Microsoft.AspNetCore.Components.Web.MouseEventArgs>(this, 
#nullable restore
#line 15 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                                        CaptureStop

#line default
#line hidden
#nullable disable
            ));
            __builder.AddContent(16, "Stop Capture");
            __builder.CloseElement();
            __builder.AddMarkupContent(17, "\r\n<br>\r\n<br>");
#nullable restore
#line 19 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
 if (packets != null)
{

#line default
#line hidden
#nullable disable
            __builder.OpenElement(18, "table");
            __builder.AddAttribute(19, "class", "table table-striped");
            __builder.AddMarkupContent(20, "<thead><tr><th>Time</th>\r\n            <th>Packet</th>\r\n            <th>Sender</th>\r\n            <th>Receiver</th></tr></thead>\r\n    ");
            __builder.OpenElement(21, "tbody");
#nullable restore
#line 31 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
         foreach (var packet in packets.ToList())
        {

#line default
#line hidden
#nullable disable
            __builder.OpenElement(22, "tr");
#nullable restore
#line 34 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                 if (packet.Ipv4Tcp)
                {

#line default
#line hidden
#nullable disable
            __builder.OpenElement(23, "td");
            __builder.AddContent(24, 
#nullable restore
#line 36 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                         DateTime.Now.TimeOfDay

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(25, "\r\n                    ");
            __builder.OpenElement(26, "td");
            __builder.AddContent(27, 
#nullable restore
#line 38 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                         packet.basePacket

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(28, "\r\n                    ");
            __builder.OpenElement(29, "td");
            __builder.AddContent(30, 
#nullable restore
#line 41 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                         packet.sender

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(31, "\r\n                    ");
            __builder.OpenElement(32, "td");
            __builder.AddContent(33, 
#nullable restore
#line 44 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                         packet.receiver

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
#nullable restore
#line 46 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                }
                else
                {

#line default
#line hidden
#nullable disable
            __builder.OpenElement(34, "td");
            __builder.AddAttribute(35, "colspan", "3");
            __builder.AddContent(36, 
#nullable restore
#line 50 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                         packet.basePacket

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
#nullable restore
#line 52 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                }

#line default
#line hidden
#nullable disable
            __builder.CloseElement();
#nullable restore
#line 54 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
        }

#line default
#line hidden
#nullable disable
            __builder.CloseElement();
            __builder.CloseElement();
#nullable restore
#line 57 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
}

#line default
#line hidden
#nullable disable
        }
        #pragma warning restore 1998
#nullable restore
#line 59 "C:\Users\finazzi.17122\Documents\GitHub\WebSniffer\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
       
    public class TablePacket
    {
        
        public bool Ipv4Tcp { get; set; }
        public string basePacket { get; set; }
        public TablePacket(string packet)
        {
            Ipv4Tcp = false;
            basePacket = packet;
        }
        public TablePacket(string packet, string sender, string receiver)
        {
            Ipv4Tcp = true;
            basePacket = packet;
            this.sender = sender;
            this.receiver = receiver;
        }
        public string sender { get; set; }
        public string receiver { get; set; }
    }

    [Parameter]
    public string ip { get; set; }

    public static ICaptureDevice device { get; set; }
    public string[] devicePorp { get; set; }
    public static List<TablePacket> packets { get; set; }

    protected void CaptureStop()
    {
        var device = CaptureDeviceList.Instance.First(x => parseDevice(x)[1] == ip);
        devicePorp = parseDevice(device);
        if (device.Started)
        {
            device.StopCapture();
            device.Close();
        }
    }

    protected void CaptureStart()
    {
        packets = new List<TablePacket>();

        var device = CaptureDeviceList.Instance.First(x => parseDevice(x)[1] == ip);
        devicePorp = parseDevice(device);

        if (!device.Started)
        {
            device.Open();
            device.OnPacketArrival += Device_OnPacketArrival;
            device.Filter = "ip and tcp";
            device.StartCapture();
        }
    }

    private void Device_OnPacketArrival(object s, PacketCapture e)
    {
        var packet = Packet.ParsePacket(e.Device.LinkType, e.Data.ToArray());
        string tablePacket = packet.ToString().Replace("][", "]\n\n[");
        if (packet != null && packet.PayloadPacket != null && packet.PayloadPacket.PayloadPacket != null &&
            packet.PayloadPacket.GetType() == typeof(IPv4Packet) &&
            packet.PayloadPacket.PayloadPacket.GetType() == typeof(TcpPacket))
        {
            var ipv4 = (IPv4Packet)packet.PayloadPacket;
            var tcp = (TcpPacket)ipv4.PayloadPacket;

            string sender = "";
            try { sender += Dns.GetHostEntry(ipv4.SourceAddress).HostName; }
            catch { sender += ipv4.SourceAddress; }
            sender += $" :{tcp.SourcePort}";

            string receiver = "";
            try { receiver += Dns.GetHostEntry(ipv4.DestinationAddress).HostName; }
            catch { receiver += ipv4.DestinationAddress; }
            receiver += $" :{tcp.DestinationPort}";

            packets.Add(new TablePacket(tablePacket, sender, receiver));
        }
        else
        {
            packets.Add(new TablePacket(tablePacket));
        }

        InvokeAsync(StateHasChanged);
    }

    protected override void OnInitialized()
    {
        if (ip != null)
        {
            var device = CaptureDeviceList.Instance.First(x => parseDevice(x)[1] == ip);
            devicePorp = parseDevice(device);
        }
    }


    protected string[] parseDevice(ICaptureDevice dev)
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

#line default
#line hidden
#nullable disable
    }
}
#pragma warning restore 1591
