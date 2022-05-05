using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebSniffer.Pages
{
    public class InterfaceModel : PageModel
    {
        [Parameter]
        public string ip { get; set; }

        public void OnGet()
        {

        }
    }
}
