using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace AuthLawan.Models.DTOs
{
    public class UserRegistrationRequestDto
    {

        [Required (ErrorMessage = "Name is required")] 
        public string Name { get; set; } = "";

        [Required (ErrorMessage = "Password is required"), MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]

        public string Password { get; set; }

        [Required (ErrorMessage = "Email is required"), DataType(DataType.EmailAddress)] 
        [EmailAddress]
        public string Email { get; set; }
    }
}