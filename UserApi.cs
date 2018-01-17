using Com.Clout2.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Com.Clout2.Api.Controllers
{
    /// <summary>
    /// Users RESTful API Controller (ASP.NET Core)
    /// </summary>
    [ApiExplorerSettings(IgnoreApi = false)]
    public class UserApiController : UserBaseApiController
    {
        /// <summary>
        /// User API Controller
        /// </summary>
        /// <param name="apiDataContext">DbContext for EntityFramework</param>
        /// <param name="logger">Injected ILoggerFactory</param>
        public UserApiController(ApiDataContext apiDataContext, ILoggerFactory logger) : base(apiDataContext, logger)
        { 
        }

		/// <summary>
		/// Create user
		/// </summary>
		/// <remarks>This can only be done by the logged in user.</remarks>
		/// <param name="loginToken">The token for the user requesting this data. If provided, Clout verifies the user rights to access the data</param>
		/// <param name="body">Created user object</param>
		/// <response code="200">successful operation</response>
		/// <response code="400">User already exists in the system</response>
		/// <response code="403">Not authorized to create user</response>
		[HttpPost]
		[Route("/users")]
		[ProducesResponseType(typeof(User), 200)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult CreateUser([FromQuery]string loginToken, [FromBody]User body)
		{
			var loggedInUser = _tokenizer.ValidateToken(loginToken);
			if ((loggedInUser != null) && (body != null))
			{
				var checkExist = _dbContext.Users.SingleOrDefault(u => u.Username == body.Username);

				if (checkExist == null)
				{
					body.CloutId = body.CloutId ?? DateTime.Now.ToString();
					body.MemberSince = body.MemberSince ?? DateTime.Now;
					body.Password = GetSHA1HashData(body.Password);
					_dbContext.Users.Add(body);
					_dbContext.SaveChanges();

					var user = _dbContext.Users.SingleOrDefault(m => m.CloutId == body.CloutId);
					if (user != null)
					{
						/*
						 * Create an email and shopper record for the new User
						 */
						var email = new Email()
						{
							UserId = user.Id,
							EmailAddress = user.Username,
							IsPrimary = "Y"
						};
						_dbContext.Emails.Add(email);
						_dbContext.SaveChanges();

						var shopper = new Shopper()
						{
							UserId = user.Id,
							NotifyEmailId = email.Id,
							FirstName = body.FirstName,
							LastName = body.LastName
						};
						_dbContext.Shoppers.Add(shopper);
						_dbContext.SaveChanges();

						user.ShopperId = shopper.Id;
						_dbContext.SaveChanges();
					}
				}
				else
				{
					return BadRequest("User already exists in the system");
				}
				if (body != null && body.Id != null) return new OkObjectResult(body);
				else return NotFound();
			}
			else return BadRequest();
		}

		/// <summary>
		/// Get user by user id
		/// </summary>
		/// <remarks></remarks>
		/// <param name="loginToken">The token for the user requesting this data. If provided, Clout verifies the user rights to access the data</param>
		/// <param name="id">The internal Clout Refernce number for the user</param>
		/// <response code="200">successful operation</response>
		/// <response code="400">Invalid username supplied</response>
		/// <response code="404">User not found</response>
		[HttpGet]
		[Route("/users")]
		[ProducesResponseType(typeof(User), 200)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult GetUserById([FromQuery]string loginToken, [FromQuery]long? id)
		{
			var loggedInUser = _tokenizer.ValidateToken(loginToken);
			if (loggedInUser != null)
			{
				if (id == null || id < 1) return new OkObjectResult(default(User));
				var result = _dbContext.Users
					.Include("Emails")
					.Include("Phones")
					.Include("Addresses")
					//.Include("BankAccountTokens")
					//.Include("Accounts")
					.SingleOrDefault(m => m.Id == id);
				if (result == null) return NotFound();
				return new OkObjectResult(result);
			}
			else return BadRequest();
		}

		/// <summary>
		/// Get user by username
		/// </summary>
		/// <remarks></remarks>
		/// <param name="loginToken">The token for the user requesting this data. If provided, Clout verifies the user rights to access the data</param>
		/// <param name="username">The name that needs to be fetched. Use user1 for testing.</param>
		/// <response code="200">successful operation</response>
		/// <response code="400">Invalid username supplied</response>
		/// <response code="404">User not found</response>
		[HttpGet]
		[Route("/user/username")]
		[ProducesResponseType(typeof(User), 200)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult GetUserByName([FromQuery]string loginToken, [FromQuery]string username)
		{
			var loggedInUser = _tokenizer.ValidateToken(loginToken);
			if (loggedInUser != null)
			{
				if (username != null)
				{
					var user = _dbContext.Users.Where(m => m.Username == username)
						.Include("Emails")
						.Include("Addresses")
						.Include("Phones")
						.Include("Contacts")
						.Include("UserRoles")
						.SingleOrDefault();
					if (user == null)
					{
						return NotFound("User was NOT found");
					}

					return new OkObjectResult(user);
				}
				else return BadRequest("Username required");
			}
			else return BadRequest();
		}

		/// <summary>
		/// Search if username exists
		/// </summary>
		/// <remarks></remarks>
		/// <param name="username">The name that needs to be fetched. Use user1 for testing.</param>
		/// <response code="200">successful operation</response>
		/// <response code="404">User not found</response>
		[HttpGet]
		[Route("/users/exists")]
		[ProducesResponseType(typeof(User), 200)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult UserExists([FromQuery]string username)
		{
			if (username != null)
			{
				var users = _dbContext.Users.Where(m => m.Username == username).ToList();
				if (users.Count == 0) return NotFound("User was NOT found");
				return Ok("User was found");
			}
			else return BadRequest("Username required");
		}

		/// <summary>
		/// Returns a blank user object to be filled out
		/// </summary>
		/// <remarks></remarks>
		/// <response code="200">successful operation</response>
		/// <response code="404">User not found</response>
		[HttpGet]
		[Route("/users/new")]
		[ProducesResponseType(typeof(User), 200)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult UserNew([FromQuery]List<long> userRoleIds = null)
		{
			List<long> defaultRoles = new List<long>() { 6L };
			var user = new User()
			{
				Guid = Guid.NewGuid().ToString()
			};
			if (userRoleIds.Count == 0) userRoleIds = defaultRoles;

			foreach (var roleId in userRoleIds)
			{
				var role = _dbContext.Roles.SingleOrDefault(r => r.Id == roleId);
				//user.Roles = new List<Role>();
				//if (role != null) user.Roles.Add(role);
				user.RoleId = role.Id;
			}

			return new OkObjectResult(user);
		}

		/// <summary>
		/// Logs user into the system, providing a backend-side loginToken. All update API methods require the login token.
		/// If the user is deactivated then we reactivate it
		/// </summary>
		/// <remarks></remarks>
		/// <param name="username">The user name for login</param>
		/// <param name="password">The password for login in clear text</param>
		/// <response code="200">successful operation</response>
		/// <response code="400">Invalid username/password supplied</response>
		/// <response code="403">Account blocked or unsuccessful login threshold exceeded</response>
		/// <response code="404">User not registered or registration pending</response>
		[HttpGet]
		[Route("/users/login")]
		[ProducesResponseType(typeof(string), 200)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult LoginUser([FromQuery]string username, [FromQuery]string password)
		{
			var hashedPassword = GetSHA1HashData(password);
			var user = _dbContext.Users.First(u => u.Username == username);
			if (user == null) return NotFound("User not found");
			if (user.Password == hashedPassword)
			{
				// Check if user is deactivate
				if (IsUserDeactivated(user))
				{
					ActivateUser(user);
					_dbContext.SaveChanges();
				}

				long Id = user.Id ?? default(long);
				return new OkObjectResult(_tokenizer.GetToken(Id, "login", 24));
			}
			else return NotFound("User not registered or registration pending");
		}

		private static void ActivateUser(User user)
		{
			user.IsActive = true;
			user.UserStatus = "active";
		}

		private static bool IsUserDeactivated(User user)
		{
			return user.IsActive == false && user.UserStatus.Equals("opt-out");
		}

		/// <summary>
		/// Updated user
		/// </summary>
		/// <remarks>This can only be done by the logged in user.</remarks>
		/// <param name="loginToken">The token for the user requesting this data. If provided, Clout verifies the user rights to access the data</param>
		/// <param name="body">Updated user object</param>
		/// <response code="400">Invalid user supplied</response>
		/// <response code="403">Not authorized</response>
		/// <response code="404">User not found</response>
		[HttpPut]
		[Route("/users")]
		[ProducesResponseType(204)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult UpdateUser([FromQuery]string loginToken, [FromBody]User body)
		{
			// Have not included the following fields to be updated:
			// Password, Email (list), Phone (list), Address (list), Roles(list), MemberSince 
			var loggedInUser = _tokenizer.ValidateToken(loginToken);
			if (loggedInUser != null)
			{
				//var userToUpdate = _dbContext.Users.Single(u => u.Id == body.Id);
				var userToUpdate = _dbContext.Users
									.Where(p => p.Id == body.Id)
									.Include("Emails")
									.Include("Phones")
									.Include("Addresses")
									.SingleOrDefault();

				if (userToUpdate != null)
				{

					// Update parent
					//_dbContext.Entry(userToUpdate).CurrentValues.SetValues(body);
					if (body.Born != null && !body.Born.Equals(userToUpdate.Born))
						userToUpdate.Born = body.Born;
					if (body.FirstName != null && !body.FirstName.Equals(userToUpdate.FirstName))
						userToUpdate.FirstName = body.FirstName;
					if (body.Gender != null && !body.Gender.Equals(userToUpdate.Gender))
						userToUpdate.Gender = body.Gender;
					if (body.LastName != null && !body.LastName.Equals(userToUpdate.LastName))
						userToUpdate.LastName = body.LastName;
					if (body.MemberSince != null && !body.MemberSince.Equals(userToUpdate.MemberSince))
						userToUpdate.MemberSince = body.MemberSince;
					if (body.Photo != null && !body.Photo.Equals(userToUpdate.Photo))
						userToUpdate.Photo = body.Photo;
					if (body.UserStatus != null && !body.UserStatus.Equals(userToUpdate.UserStatus))
						userToUpdate.UserStatus = body.UserStatus;
					if (body.IsActive != null && !body.IsActive.Equals(userToUpdate.IsActive))
						userToUpdate.IsActive = body.IsActive;
					if (body.CloutId != null && !body.CloutId.Equals(userToUpdate.CloutId))
						userToUpdate.CloutId = body.CloutId;
					if (body.EmailVerified != null && !body.EmailVerified.Equals(userToUpdate.EmailVerified))
						userToUpdate.EmailVerified = body.EmailVerified;
					if (body.MobileVerified != null && !body.MobileVerified.Equals(userToUpdate.MobileVerified))
						userToUpdate.MobileVerified = body.MobileVerified;
					if (body.AddressVerified != null && !body.AddressVerified.Equals(userToUpdate.AddressVerified))
						userToUpdate.AddressVerified = body.AddressVerified;
					if (body.PushNotifications != null && !body.PushNotifications.Equals(userToUpdate.PushNotifications))
						userToUpdate.PushNotifications = body.PushNotifications;
					if (body.SmsNotifications != null && !body.SmsNotifications.Equals(userToUpdate.SmsNotifications))
						userToUpdate.SmsNotifications = body.SmsNotifications;
					if (body.Guid != null && !body.Guid.Equals(userToUpdate.Guid))
						userToUpdate.Guid = body.Guid;
					if (body.Username != null && !body.Username.Equals(userToUpdate.Username))
						userToUpdate.Username = body.Username;
					if (body.ActiveBankAccount != null && !body.ActiveBankAccount.Equals(userToUpdate.ActiveBankAccount))
						userToUpdate.ActiveBankAccount = body.ActiveBankAccount;
					if (body.ActiveCreditCard != null && !body.ActiveCreditCard.Equals(userToUpdate.ActiveCreditCard))
						userToUpdate.ActiveCreditCard = body.ActiveCreditCard;
					if (body.BusinessId != null && !body.BusinessId.Equals(userToUpdate.BusinessId))
						userToUpdate.BusinessId = body.BusinessId;
					if (body.RoleId != null && !body.RoleId.Equals(userToUpdate.RoleId))
						userToUpdate.RoleId = body.RoleId;
					if (body.ShopperId != null && !body.ShopperId.Equals(userToUpdate.ShopperId))
						userToUpdate.ShopperId = body.ShopperId;
					if (body.NetworkParentId != null && !body.NetworkParentId.Equals(userToUpdate.NetworkParentId))
						userToUpdate.NetworkParentId = body.NetworkParentId;
					if (body.NetworkId != null && !body.NetworkId.Equals(userToUpdate.NetworkId))
						userToUpdate.NetworkId = body.NetworkId;
					if (body.InvitationId != null && !body.NetworkId.Equals(userToUpdate.NetworkId))
						userToUpdate.NetworkId = body.NetworkId;
					if (body.FacebookConnected != null && !body.FacebookConnected.Equals(userToUpdate.FacebookConnected))
						userToUpdate.FacebookConnected = body.FacebookConnected;
					if (body.Password != null && !GetSHA1HashData(body.Password).Equals(userToUpdate.Password))
						userToUpdate.Password = GetSHA1HashData(body.Password);
					userToUpdate.PasswordChanged = DateTime.Now;

					if (body.Emails != null)
					{
						// Add/Update Emails
						// Make all emails WITHOUT an existing id not active
						foreach (var existingChild in userToUpdate.Emails.ToList())
						{
							if (!body.Emails.Any(c => c.Id == existingChild.Id))
								existingChild.IsActive = "N";
							existingChild.IsPrimary = "N";
						}

						// Update child if it exists, else insert a new entry
						foreach (var childModel in body.Emails.ToList())
						{
							var existingChild = userToUpdate.Emails
								.Where(c => c.Id == childModel.Id)
								.SingleOrDefault();

							if (existingChild != null)
								_dbContext.Entry(existingChild).CurrentValues.SetValues(childModel);
							else
							{
								var newEmail = new Email();
								_dbContext.Entry(newEmail).CurrentValues.SetValues(childModel);
								userToUpdate.Emails.Add(newEmail);
							}
						}
					}


					// Add/Update Emails
					// Make all emails WITHOUT an existing id not active
					if (body.Phones != null)
					{
						foreach (var existingChild in userToUpdate.Phones.ToList())
						{
							if (!body.Phones.Any(c => c.Id == existingChild.Id))
								existingChild.IsActive = "N";
							existingChild.IsPrimary = "N";
						}


						// Update child if it exists, else insert a new entry
						foreach (var childModel in body.Phones.ToList())
						{
							var existingChild = userToUpdate.Phones
								.Where(c => c.Id == childModel.Id)
								.SingleOrDefault();

							if (existingChild != null)
								_dbContext.Entry(existingChild).CurrentValues.SetValues(childModel);
							else
							{
								var newPhone = new Phone();
								_dbContext.Entry(newPhone).CurrentValues.SetValues(childModel);
								userToUpdate.Phones.Add(newPhone);
							}
						}
					}

					if (body.Addresses != null)
					{
						// Add/Update Addresses
						// Make all Addresses WITHOUT an existing id not active
						foreach (var existingChild in userToUpdate.Addresses.ToList())
						{
							if (!body.Addresses.Any(c => c.Id == existingChild.Id))
								existingChild.IsActive = "N";
							existingChild.IsPrimary = "N";
						}

						// Update child if it exists, else insert a new entry
						foreach (var childModel in body.Addresses.ToList())
						{
							var existingChild = userToUpdate.Addresses
								.Where(c => c.Id == childModel.Id)
								.SingleOrDefault();

							if (existingChild != null)
								_dbContext.Entry(existingChild).CurrentValues.SetValues(childModel);
							else
							{
								var newAddress = new Address();
								_dbContext.Entry(newAddress).CurrentValues.SetValues(childModel);
								userToUpdate.Addresses.Add(newAddress);
							}
						}
					}
					//*/

					_dbContext.SaveChanges();
					return Ok("successful operation, no data returned");
				}
				else return NotFound("User not found");
			}
			else return BadRequest("User not logged in");
		}

		/// <summary>
		/// Reset user password
		/// </summary>
		/// <remarks>This can only be done by the logged in user.</remarks>
		/// <param name="loginToken">The token for the user requesting this data. If provided, Clout verifies the user rights to access the data</param>
		/// <param name="body">Updated user object</param>
		/// <response code="400">Invalid user supplied</response>
		/// <response code="403">Not authorized</response>
		/// <response code="404">User not found</response>
		[HttpPut]
		[Route("/user/reset_password")]
		[ProducesResponseType(204)]
		[ProducesResponseType(typeof(IDictionary<string, string>), 400)]
		[ApiExplorerSettings(IgnoreApi = false)]
		public virtual IActionResult ResetUserPassword([FromQuery]string loginToken, [FromBody]User body)
		{
			// Have not included the following fields to be updated:
			// Password, Email (list), Phone (list), Address (list), Roles(list), MemberSince 
			var loggedInUser = _tokenizer.ValidateToken(loginToken);
			if (loggedInUser != null)
			{
				//var userToUpdate = _dbContext.Users.Single(u => u.Id == body.Id);
				var userToUpdate = _dbContext.Users
									.Where(p => p.Id == body.Id)
									.Single();

				if (userToUpdate != null)
				{
					if (body.Born != null && !body.Born.Equals(userToUpdate.Born))
						userToUpdate.Born = body.Born;
					if (body.FirstName != null && !body.FirstName.Equals(userToUpdate.FirstName))
						userToUpdate.FirstName = body.FirstName;
					if (body.Gender != null && !body.Gender.Equals(userToUpdate.Gender))
						userToUpdate.Gender = body.Gender;
					if (body.LastName != null && !body.LastName.Equals(userToUpdate.LastName))
						userToUpdate.LastName = body.LastName;
					if (body.MemberSince != null && !body.MemberSince.Equals(userToUpdate.MemberSince))
						userToUpdate.MemberSince = body.MemberSince;
					if (body.Photo != null && !body.Photo.Equals(userToUpdate.Photo))
						userToUpdate.Photo = body.Photo;
					if (body.UserStatus != null && !body.UserStatus.Equals(userToUpdate.UserStatus))
						userToUpdate.UserStatus = body.UserStatus;
					if (body.CloutId != null && !body.CloutId.Equals(userToUpdate.CloutId))
						userToUpdate.CloutId = body.CloutId;
					if (body.EmailVerified != null && !body.EmailVerified.Equals(userToUpdate.EmailVerified))
						userToUpdate.EmailVerified = body.EmailVerified;
					if (body.MobileVerified != null && !body.MobileVerified.Equals(userToUpdate.MobileVerified))
						userToUpdate.MobileVerified = body.MobileVerified;
					if (body.AddressVerified != null && !body.AddressVerified.Equals(userToUpdate.AddressVerified))
						userToUpdate.AddressVerified = body.AddressVerified;
					if (body.PushNotifications != null && !body.PushNotifications.Equals(userToUpdate.PushNotifications))
						userToUpdate.PushNotifications = body.PushNotifications;
					if (body.SmsNotifications != null && !body.SmsNotifications.Equals(userToUpdate.SmsNotifications))
						userToUpdate.SmsNotifications = body.SmsNotifications;
					if (body.Guid != null && !body.Guid.Equals(userToUpdate.Guid))
						userToUpdate.Guid = body.Guid;
					if (body.Username != null && !body.Username.Equals(userToUpdate.Username))
						userToUpdate.Username = body.Username;
					if (body.ActiveBankAccount != null && !body.ActiveBankAccount.Equals(userToUpdate.ActiveBankAccount))
						userToUpdate.ActiveBankAccount = body.ActiveBankAccount;
					if (body.ActiveCreditCard != null && !body.ActiveCreditCard.Equals(userToUpdate.ActiveCreditCard))
						userToUpdate.ActiveCreditCard = body.ActiveCreditCard;
					if (body.BusinessId != null && !body.BusinessId.Equals(userToUpdate.BusinessId))
						userToUpdate.BusinessId = body.BusinessId;
					if (body.RoleId != null && !body.RoleId.Equals(userToUpdate.RoleId))
						userToUpdate.RoleId = body.RoleId;
					if (body.ShopperId != null && !body.ShopperId.Equals(userToUpdate.ShopperId))
						userToUpdate.ShopperId = body.ShopperId;
					if (body.NetworkParentId != null && !body.NetworkParentId.Equals(userToUpdate.NetworkParentId))
						userToUpdate.NetworkParentId = body.NetworkParentId;
					if (body.NetworkId != null && !body.NetworkId.Equals(userToUpdate.NetworkId))
						userToUpdate.NetworkId = body.NetworkId;
					if (body.InvitationId != null && !body.NetworkId.Equals(userToUpdate.NetworkId))
						userToUpdate.NetworkId = body.NetworkId;
					if (body.FacebookConnected != null && !body.FacebookConnected.Equals(userToUpdate.FacebookConnected))
						userToUpdate.FacebookConnected = body.FacebookConnected;

					userToUpdate.Password = GetSHA1HashData(body.Password);
					userToUpdate.PasswordChanged = DateTime.Now;
					_dbContext.SaveChanges();
					return Ok("successful operation, no data returned");
				}
				else return NotFound("User not found");
			}
			else return BadRequest("User not logged in");
		}

		/// <summary>
		/// take any string and encrypt it using SHA1 then
		/// return the encrypted data. This is the password Encryption algorithm used
		/// in the CodeIgniter version of the Clout Stack
		/// </summary>
		/// <param name="data">input text you will enterd to encrypt it</param>
		/// <returns>return the encrypted text as hexadecimal string</returns>
		private string GetSHA1HashData(string data)
		{
			StringBuilder returnValue = new StringBuilder();
			//create new instance of md5
			using (var sha1 = SHA1.Create())
			{
				//convert the input text to array of bytes
				// PHP uses Ascii encoding
				var hashData = sha1.ComputeHash(Encoding.ASCII.GetBytes(data));
				//loop for each byte and add it to StringBuilder
				foreach (var b in hashData)
				{
					returnValue.Append(b.ToString("x2"));
				}
			}
			return returnValue.ToString();
		}
    }
}
