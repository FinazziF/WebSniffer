using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebSniffer.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {

        }

        [BindProperty]
        public List<string[]> deviceList { get; set; }

        public void OnGetInterfaces()
        {
            deviceList = new List<string[]>();
            foreach (ICaptureDevice dev in LibPcapLiveDeviceList.Instance)
            {
                deviceList.Add(parseDevice(dev));
            }
        }

        public ActionResult OnPostRedirect(string ip)
        {            
            return Redirect($"/Interface/{ip}");
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
