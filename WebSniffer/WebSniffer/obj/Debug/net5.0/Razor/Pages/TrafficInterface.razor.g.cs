#pragma checksum "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "80739d491e26b0d98ab80d5513ce5393038d764d"
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
#line 3 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using SharpPcap;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using PacketDotNet;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using System.Net;

#line default
#line hidden
#nullable disable
#nullable restore
#line 6 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using Microsoft.AspNetCore.Components;

#line default
#line hidden
#nullable disable
#nullable restore
#line 7 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using Microsoft.AspNetCore.Components.Web;

#line default
#line hidden
#nullable disable
#nullable restore
#line 8 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using System.IO;

#line default
#line hidden
#nullable disable
#nullable restore
#line 9 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using Newtonsoft.Json;

#line default
#line hidden
#nullable disable
#nullable restore
#line 10 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using System.Text;

#line default
#line hidden
#nullable disable
#nullable restore
#line 11 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
using Microsoft.JSInterop;

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
#line 17 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
             devicePorp[0]

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(2, "\r\n        ");
            __builder.OpenElement(3, "h3");
            __builder.AddContent(4, 
#nullable restore
#line 18 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
             devicePorp[1]

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(5, "\r\n        <br>\r\n        ");
            __builder.OpenElement(6, "table");
            __builder.AddAttribute(7, "class", "table table-bordered");
            __builder.AddAttribute(8, "style", " text-align: center");
            __builder.OpenElement(9, "tr");
            __builder.OpenElement(10, "th");
            __builder.AddMarkupContent(11, "<br>\r\n\r\n                    ");
            __builder.OpenElement(12, "button");
            __builder.AddAttribute(13, "class", "btn btn-success");
            __builder.AddAttribute(14, "type", "submit");
            __builder.AddAttribute(15, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create<Microsoft.AspNetCore.Components.Web.MouseEventArgs>(this, 
#nullable restore
#line 25 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                                                            CaptureStart

#line default
#line hidden
#nullable disable
            ));
            __builder.AddContent(16, "Start Capture");
            __builder.CloseElement();
            __builder.AddMarkupContent(17, "\r\n                    <br>\r\n\r\n                    <br>\r\n                    ");
            __builder.OpenElement(18, "form");
            __builder.OpenElement(19, "div");
            __builder.AddAttribute(20, "class", "form-group");
            __builder.AddMarkupContent(21, "\r\n                            Number of packets shown\r\n                            ");
            __builder.OpenElement(22, "input");
            __builder.AddAttribute(23, "value", Microsoft.AspNetCore.Components.BindConverter.FormatValue(
#nullable restore
#line 32 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                          maxNumPackets

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(24, "onchange", Microsoft.AspNetCore.Components.EventCallback.Factory.CreateBinder(this, __value => maxNumPackets = __value, maxNumPackets));
            __builder.SetUpdatesAttributeName("value");
            __builder.CloseElement();
            __builder.CloseElement();
            __builder.CloseElement();
            __builder.AddMarkupContent(25, "\r\n\r\n                    ");
            __builder.OpenElement(26, "div");
            __builder.AddMarkupContent(27, "\r\n                        Only Show Ip and Tcp Traffic:\r\n                        ");
            __builder.OpenElement(28, "input");
            __builder.AddAttribute(29, "type", "checkbox");
            __builder.AddAttribute(30, "checked", Microsoft.AspNetCore.Components.BindConverter.FormatValue(
#nullable restore
#line 38 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                                       onlyTcpIp

#line default
#line hidden
#nullable disable
            ));
            __builder.AddAttribute(31, "onchange", Microsoft.AspNetCore.Components.EventCallback.Factory.CreateBinder(this, __value => onlyTcpIp = __value, onlyTcpIp));
            __builder.SetUpdatesAttributeName("checked");
            __builder.CloseElement();
            __builder.CloseElement();
            __builder.AddMarkupContent(32, "\r\n                    <br>\r\n                    ");
            __builder.OpenElement(33, "button");
            __builder.AddAttribute(34, "class", "btn btn-primary");
            __builder.AddAttribute(35, "type", "submit");
            __builder.AddAttribute(36, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create<Microsoft.AspNetCore.Components.Web.MouseEventArgs>(this, 
#nullable restore
#line 41 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                                                            JsonList

#line default
#line hidden
#nullable disable
            ));
            __builder.AddMarkupContent(37, "\r\n                        Download Capture ");
            __builder.AddMarkupContent(38, @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""16"" height=""16"" fill=""currentColor"" class=""bi bi-cloud-download"" viewBox=""0 0 16 16""><path d=""M4.406 1.342A5.53 5.53 0 0 1 8 0c2.69 0 4.923 2 5.166 4.579C14.758 4.804 16 6.137 16 7.773 16 9.569 14.502 11 12.687 11H10a.5.5 0 0 1 0-1h2.688C13.979 10 15 8.988 15 7.773c0-1.216-1.02-2.228-2.313-2.228h-.5v-.5C12.188 2.825 10.328 1 8 1a4.53 4.53 0 0 0-2.941 1.1c-.757.652-1.153 1.438-1.153 2.055v.448l-.445.049C2.064 4.805 1 5.952 1 7.318 1 8.785 2.23 10 3.781 10H6a.5.5 0 0 1 0 1H3.781C1.708 11 0 9.366 0 7.318c0-1.763 1.266-3.223 2.942-3.593.143-.863.698-1.723 1.464-2.383z""></path>
                            <path d=""M7.646 15.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 14.293V5.5a.5.5 0 0 0-1 0v8.793l-2.146-2.147a.5.5 0 0 0-.708.708l3 3z""></path></svg>");
            __builder.CloseElement();
            __builder.AddMarkupContent(39, "\r\n                    <br>");
            __builder.CloseElement();
            __builder.AddMarkupContent(40, "\r\n                ");
            __builder.OpenElement(41, "th");
            __builder.AddAttribute(42, "style", "vertical-align : middle");
            __builder.AddAttribute(43, "rowspan", "2");
            __builder.OpenElement(44, "button");
            __builder.AddAttribute(45, "class", "btn btn-danger");
            __builder.AddAttribute(46, "type", "submit");
            __builder.AddAttribute(47, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create<Microsoft.AspNetCore.Components.Web.MouseEventArgs>(this, 
#nullable restore
#line 51 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                                                           CaptureStop

#line default
#line hidden
#nullable disable
            ));
            __builder.AddContent(48, "Stop Capture");
            __builder.CloseElement();
            __builder.CloseElement();
            __builder.CloseElement();
            __builder.CloseElement();
#nullable restore
#line 57 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
         if (packetQueue != null)
        {

#line default
#line hidden
#nullable disable
            __builder.OpenElement(49, "div");
            __builder.AddAttribute(50, "style", "height: 50rem; overflow: auto; table-layout: fixed");
            __builder.OpenElement(51, "table");
            __builder.AddAttribute(52, "class", "table table-striped");
            __builder.AddMarkupContent(53, "<thead><tr><th>#</th>\r\n                            <th>Packet</th>\r\n                            <th>Sender</th>\r\n                            <th>Receiver</th>\r\n                            <th>Time</th></tr></thead>\r\n                    ");
            __builder.OpenElement(54, "tbody");
#nullable restore
#line 71 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                         foreach (var packet in ReverseQueue())
                        {

#line default
#line hidden
#nullable disable
            __builder.OpenElement(55, "tr");
#nullable restore
#line 74 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                 if (packet.Ipv4Tcp)
                                {

#line default
#line hidden
#nullable disable
            __builder.OpenElement(56, "td");
            __builder.AddContent(57, 
#nullable restore
#line 76 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         packet.id

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(58, "\r\n                                    ");
            __builder.OpenElement(59, "td");
            __builder.AddContent(60, 
#nullable restore
#line 78 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         packet.basePacket

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(61, "\r\n                                    ");
            __builder.OpenElement(62, "td");
            __builder.AddContent(63, 
#nullable restore
#line 81 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         packet.sender

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(64, "\r\n                                    ");
            __builder.OpenElement(65, "td");
            __builder.AddContent(66, 
#nullable restore
#line 84 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         packet.receiver

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(67, "\r\n                                    ");
            __builder.OpenElement(68, "td");
            __builder.AddContent(69, 
#nullable restore
#line 86 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         DateTime.Now.TimeOfDay

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
#nullable restore
#line 87 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                }
                                else
                                {

#line default
#line hidden
#nullable disable
            __builder.OpenElement(70, "td");
            __builder.AddContent(71, 
#nullable restore
#line 90 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         packet.id

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(72, "\r\n                                    ");
            __builder.OpenElement(73, "td");
            __builder.AddContent(74, 
#nullable restore
#line 92 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         packet.basePacket

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.AddMarkupContent(75, "\r\n                                    ");
            __builder.AddMarkupContent(76, "<td>\r\n                                        Not available\r\n                                    </td>\r\n                                    ");
            __builder.AddMarkupContent(77, "<td>\r\n                                        Not available\r\n                                    </td>\r\n                                    ");
            __builder.OpenElement(78, "td");
            __builder.AddContent(79, 
#nullable restore
#line 100 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                         DateTime.Now.TimeOfDay

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
#nullable restore
#line 101 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                                }

#line default
#line hidden
#nullable disable
            __builder.CloseElement();
#nullable restore
#line 103 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
                        }

#line default
#line hidden
#nullable disable
            __builder.CloseElement();
            __builder.CloseElement();
            __builder.CloseElement();
#nullable restore
#line 107 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
        }

#line default
#line hidden
#nullable disable
        }
        #pragma warning restore 1998
#nullable restore
#line 110 "D:\Progetti\WebSniffer\WebSniffer\WebSniffer\Pages\TrafficInterface.razor"
       
    
    public class TablePacket
    {
        public int id { get; set; }
        public bool Ipv4Tcp { get; set; }
        public string basePacket { get; set; }
        public TablePacket(string packet, int id)
        {
            Ipv4Tcp = false;
            basePacket = packet;
            this.id = id;
        }
        public TablePacket(string packet, string sender, string receiver, int id)
        {
            Ipv4Tcp = true;
            basePacket = packet;
            this.sender = sender;
            this.receiver = receiver;
            this.id = id;
        }
        public string sender { get; set; }
        public string receiver { get; set; }
    }

    public List<TablePacket> ReverseQueue()
    {
        return packetQueue.Reverse<TablePacket>().ToList();
    }

    protected bool onlyTcpIp { get; set; }
    [Parameter]
    public string ip { get; set; }

    public int packetCount { get; set; }
    public int maxNumPackets { get; set; }
    public static ICaptureDevice device { get; set; }
    public string[] devicePorp { get; set; }
    public static List<TablePacket> packets { get; set; }
    public static Queue<TablePacket> packetQueue { get; set; }

    protected async Task JsonList()
    {
        var list = ReverseQueue();
        if (list.Any())
        {
            Encoding u8 = Encoding.UTF8;
            var a = JsonConvert.SerializeObject(list, Formatting.Indented).ToString();
            var byteArr = JsonConvert.SerializeObject(list, Formatting.Indented).ToString().ToList().Select(c => (byte)c).ToArray();

            await JS.InvokeVoidAsync("downloadFile", "text/plain", Convert.ToBase64String(byteArr), "packetCapture.json");
        }
    }

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
        packetQueue = new Queue<TablePacket>();
        packetCount = 0;
        if (maxNumPackets != 0)
        {

            var device = CaptureDeviceList.Instance.First(x => parseDevice(x)[1] == ip);
            devicePorp = parseDevice(device);

            if (!device.Started)
            {
                device.Open();
                device.OnPacketArrival += Device_OnPacketArrival;
                if (onlyTcpIp)
                    device.Filter = "ip and tcp";
                device.StartCapture();
            }
        }
    }

    private void Device_OnPacketArrival(object s, PacketCapture e)
    {
        packetCount++;
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

            PushPopPackets(new TablePacket(tablePacket, sender, receiver, packetCount));
        }
        else
        {
            PushPopPackets(new TablePacket(tablePacket, packetCount));
        }

        InvokeAsync(StateHasChanged);
    }

    protected void PushPopPackets(TablePacket tPacket)
    {
        if (packetQueue.Count() > maxNumPackets - 1)
        {
            packetQueue.Dequeue();
        }
        packetQueue.Enqueue(tPacket);
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
        [global::Microsoft.AspNetCore.Components.InjectAttribute] private IJSRuntime JS { get; set; }
    }
}
#pragma warning restore 1591
