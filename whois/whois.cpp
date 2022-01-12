#include "whois.h"

// -----
// User functions
// -----

// This will set the user
void whois::setUser(User user)
{
	this->user = user;
}

// This will return the current user stored in the whoami class
User whois::getUser()
{
	return this->user;
}

// ----
// Command functions
// ----

// If a command name is provided, check to see if it is a valid command
// If it is, return the commands help string
// if not, print the program help string
void whois::help(string command)
{
	// Check if a command name is provided
	if (command.length() > 0)
	{
		// Check if the command is in the command map
		if (this->commands.find(command) != this->commands.end())
		{
			// Get the help string for the command
			string help = this->commands[command].help;
			// Print the help string
			cout << help << endl;
		}
		else
		{
			// Print all the commands
			cout << "Available commands:" << endl;
			for (auto cmd : this->commands)
			{
				// Print the command name and the help string
				cout << cmd.first << " - " << cmd.second.help << endl;
			}
		}
	}
	else
	{
		// Print all the commands
		cout << "Available commands:" << endl;
		for (auto cmd : this->commands)
		{
			// Print the command name and the help string
			cout << cmd.first << " - " << cmd.second.help << endl;
		}
	}
}

LDAP *whois::auth()
{
	// Create a PWCHAR version of the hostname
	PWCHAR hostname = nullptr;
	size_t origsize = strlen(this->host) + 1;
	size_t convertedChars = 0;
	wchar_t wcstring[100];
	// ???
	mbstowcs_s(&convertedChars, wcstring, origsize, this->host, _TRUNCATE);
	wcscat_s(wcstring, L" (wchar_t *)");
	hostname = wcstring;

	// -----
	// Initialize the LDAP instance
	// -----
	LDAP *ld = ldap_init(hostname, LDAP_PORT);
	if (ld == NULL)
	{
		// If the LDAP instance is null, print an error message
		cout << "Error: Could not initialize LDAP instance" << endl;
		return NULL;
	}

	// -----
	// Set the session options
	// -----
	int version = LDAP_VERSION3;
	int numReturns = 10;
	ULONG lRtn;

	// Set the LDAP version
	lRtn = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (lRtn != LDAP_SUCCESS)
	{
		// If the LDAP version is not set, print an error message
		cout << "Error: Could not set LDAP version" << endl;
		return NULL;
	}

	// Set the number of results to return
	lRtn = ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &numReturns);
	if (lRtn != LDAP_SUCCESS)
	{
		// If the number of results to return is not set, print an error message
		cout << "Error: Could not set number of results to return" << endl;
		return NULL;
	}

	// -----
	// Connect to the server
	// -----
	lRtn = ldap_connect(ld, nullptr);
	if (lRtn != LDAP_SUCCESS)
	{
		// If the server could not be connected, print the error string with its id
		printf("Error: Could not connect to server: 0x%x\n", lRtn);

		return NULL;
	}

	// -----
	// Bind to the server
	// -----
	lRtn = ldap_bind_sW(ld, nullptr, nullptr, LDAP_AUTH_NTLM);
	if (lRtn != LDAP_SUCCESS)
	{
		// Print a success message and the hex of lRtn
		printf("Error: Could not bind to server. lRtn -> 0x%x\n", lRtn);
		return NULL;
	}

	this->ldap = ld;
	return ld;
}

void whois::search(string query)
{
	// Check if the LDAP instance is null
	if (this->ldap == NULL)
	{
		// If the LDAP instance is null, print an error message
		cout << "Error: LDAP instance is null" << endl;
		return;
	}

	// Check if the query is empty
	if (query.length() == 0)
	{
		// If the query is empty, print an error message
		cout << "Error: Query is empty" << endl;
		return;
	}

	// -----
	// Define the filter and attributes
	// -----
	// We want all the attributes defined in the user struct
	const char *attrs[] = {nullptr};

	// The user is able to input multiple things as a query so first we need to figure out what the user is looking for
	// If the query is a name with a space, we will use the name attribute
	// if the query is an email, we will use the email attribute
	// If the query is just one word without a space, we will use the sAMAccountName attribute

	// Define the type
	// 0 - name
	// 1 - email
	// 2 - sAMAccountName
	int type = 0;

	// Check the query for spaces
	if (query.find(" ") != string::npos)
	{
		// If the query has spaces, we will use the name attribute
		type = 0;
	}
	else if (query.find("@") != string::npos)
	{
		// If the query has an @, we will use the email attribute
		type = 1;
	}
	else
	{
		// If the query does not have spaces or an @, we will use the sAMAccountName attribute
		type = 2;
	}

	// Define the filter
	string filter;
	switch (type)
	{
	case 0:
		// If the type is name, we will use the name attribute
		filter = "(&(objectClass=user)(Name=" + query + "))";
		break;
	case 1:
		// If the type is email, we will use the email attribute
		filter = "(&(objectClass=user)(mail=" + query + "))";
		break;
	case 2:
		// If the type is sAMAccountName, we will use the sAMAccountName attribute
		filter = "(&(objectClass=user)(SamAccountName=" + query + "))";
		break;
	}

	// Convert the filter to PWSTR
	PWCHAR filterW = nullptr;
	size_t origsize = strlen(filter.c_str()) + 1;
	size_t convertedChars = 0;
	wchar_t wcstring[100];
	mbstowcs_s(&convertedChars, wcstring, origsize, filter.c_str(), _TRUNCATE);
	filterW = wcstring;

	// Convert the base to PWSTR
	PWCHAR baseW = nullptr;
	size_t borigsize = strlen(this->base) + 1;
	size_t bconvertedChars = 0;
	wchar_t bwcstring[100];
	mbstowcs_s(&bconvertedChars, bwcstring, borigsize, this->base, _TRUNCATE);
	baseW = bwcstring;

	// -----
	// Search the server
	// -----
	LDAPMessage *res;

	int lRtn = ldap_search_ext_sW(this->ldap, baseW, LDAP_SCOPE_SUBTREE, filterW, (PZPWSTR)attrs, 0, nullptr, nullptr, nullptr, 0, &res);
	if (lRtn != LDAP_SUCCESS)
	{
		// If the search failed, print an error message and the hex of lRtn
		printf("Error: Could not search server. lRtn -> 0x%x\n", lRtn);
		return;
	}

	// -----
	// Count the number of results
	// -----
	int numResults = ldap_count_entries(this->ldap, res);
	if (numResults == 0)
	{
		// If there are no results, print an error message
		cout << "Error: No results found" << endl;
		return;
	}

	// -----
	// Get the first entry
	// -----
	LDAPMessage *entry = ldap_first_entry(this->ldap, res);
	if (entry == NULL)
	{
		// If the entry is null, print an error message
		cout << "Error: Could not find user" << endl;
		return;
	}

	// -----
	// Set the entry
	// -----
	this->entry = entry;

	// -----
	// Get the attributes defined in the user struct
	// -----

	// Get CN
	PCHAR *cn = nullptr;
	cn = ldap_get_valuesA(this->ldap, entry, PSTR("cn"));
	if (cn != nullptr)
	{
		this->user.cn = cn[0];
	}

	// Get department
	PCHAR *department = nullptr;
	department = ldap_get_valuesA(this->ldap, entry, PSTR("department"));
	if (department != nullptr)
	{
		this->user.department = department[0];
	}

	// Get description
	PCHAR *description = nullptr;
	description = ldap_get_valuesA(this->ldap, entry, PSTR("description"));
	if (description != nullptr)
	{
		this->user.description = description[0];
	}

	// Get employeeID
	PCHAR *employeeID = nullptr;
	employeeID = ldap_get_valuesA(this->ldap, entry, PSTR("employeeID"));
	if (employeeID != nullptr)
	{
		this->user.employeeid = employeeID[0];
	}

	// Get mail
	PCHAR *mail = nullptr;
	mail = ldap_get_valuesA(this->ldap, entry, PSTR("mail"));
	if (mail != nullptr)
	{
		this->user.email = mail[0];
	}

	// Get name
	PCHAR *name = nullptr;
	name = ldap_get_valuesA(this->ldap, entry, PSTR("name"));
	if (name != nullptr)
	{
		this->user.name = name[0];
	}

	// Get sAMAccountName
	PCHAR *sAMAccountName = nullptr;
	sAMAccountName = ldap_get_valuesA(this->ldap, entry, PSTR("sAMAccountName"));
	if (sAMAccountName != nullptr)
	{
		this->user.samaccountname = sAMAccountName[0];
	}

	// Get title
	PCHAR *title = nullptr;
	title = ldap_get_valuesA(this->ldap, entry, PSTR("title"));
	if (title != nullptr)
	{
		this->user.title = title[0];
	}

	// -----
	// Pretty print the user
	// -----

	// Call info
	this->info();
}

void whois::info()
{
	// Pretty print all the user's attributes

	// Print a buffer
	printf("\n");

	// Print the user's common name
	printf("Common name: %s\n", this->user.cn);

	// Print the user's department
	printf("Department: %s\n", this->user.department);

	// Print the user's description
	printf("Description: %s\n", this->user.description);

	// Print the user's employee ID
	printf("Employee ID: %s\n", this->user.employeeid);

	// Print the user's email
	printf("Email: %s\n", this->user.email);

	// Print the user's full name
	printf("Full name: %s\n", this->user.name);

	// Print the user's account name
	printf("Account name: %s\n", this->user.samaccountname);

	// Print the user's title
	printf("Title: %s\n", this->user.title);

	// Print a buffer
	printf("\n");
}

void whois::remote()
{
	// Check if the user struct is empty
	if (this->user.samaccountname == "")
	{
		// If it is, print an error message
		cout << "Error: No user selected" << endl;
		return;
	}

	// Check if the user has a description
	if (this->user.description == "")
	{
		// If it doesn't, print an error message
		cout << "Error: No description found" << endl;
		return;
	}

	// Parse the description to extract last computer and logon time
	// The computer name will always be after "Last Logon: " and before " at " and the logon time will always be after " at "

	// Get the description
	string description = this->user.description;

	// Get the computer name
	string computer_name = description.substr(description.find("Last Logon: ") + 12, description.find(" at ") - description.find("Last Logon: ") - 12);

	// Start a new process
	// The exe is located at "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\i386\CmRcViewer.exe"
	// Start the process with the user's computer name as the argument
	string command = "C:\\Program Files (x86)\\Microsoft Configuration Manager\\AdminConsole\\bin\\i386\\CmRcViewer.exe " + computer_name;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void whois::quit()
{
	// Close the LDAP connection
	ldap_unbind_s(this->ldap);

	// Close the program
	exit(0);
}
