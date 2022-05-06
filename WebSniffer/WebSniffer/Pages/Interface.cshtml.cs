using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebSniffer.Pages
{
    public class InterfaceModel : PageModel
    {
        [Parameter]
        public static string ip { get; set; }

        public string GetIp() 
        {
            return Request.Path.ToString().Split('/')[2];
        }        
        public void OnGet(string ip)
        {
            string a = "asdfasdfasf";
        }
    }
}
